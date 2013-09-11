import logging, os, re, time, codecs
from autotest.client import utils
from autotest.client.shared import error
from virttest import utils_test, virsh, utils_libvirtd, remote
from virttest.libvirt_xml import vm_xml


def run_virsh_migrate(test, params, env):
    """
    Test virsh migrate command.
    """

    def check_vm_state(vm, state):
        """
        Return True if vm is in the correct state.
        """
        actual_state = vm.state()
        if cmp(actual_state, state) == 0:
            return True
        else:
            return False

    def cleanup_dest(vm, src_uri=""):
        """
        Clean up the destination host environment
        when doing the uni-direction migration.
        """
        logging.info("Cleaning up VMs on %s" % vm.connect_uri)
        try:
            if virsh.domain_exists(vm.name, uri=vm.connect_uri):
                vm_state = vm.state()
                if vm_state == "paused":
                    vm.resume()
                elif vm_state == "shut off":
                    vm.start()
                vm.destroy()

                if vm.is_persistent():
                    vm.undefine()

        except Exception, detail:
            logging.error("Cleaning up destination failed.\n%s" % detail)

        if src_uri:
            vm.connect_uri = src_uri

    def do_migration(delay, vm, dest_uri, options, extra):
        logging.info("Sleeping %d seconds before migration" % delay)
        time.sleep(delay)
        # Migrate the guest.
        successful = vm.migrate(dest_uri, options, extra, True, True).exit_status
        logging.info("successful: %d", successful)
        if int(successful) != 0:
            logging.error("Migration failed for %s." % vm_name)
            return False

        if options.count("dname") or extra.count("dname"):
            vm.name = extra.split()[1].strip()

        if vm.is_alive(): # vm.connect_uri was updated
            logging.info("Alive guest found on destination %s." % dest_uri)
        else:
            logging.error("VM not alive on destination %s" % dest_uri)
            return False

        # Throws exception if console shows panic message
        vm.verify_kernel_crash()
        return True


    vm_name = params.get("main_vm")
    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()

    # For safety reasons, we'd better back up  xmlfile.
    vm_xmlfile_bak = vm.backup_xml()
    if not vm_xmlfile_bak:
        logging.error("Backing up xmlfile failed.")

    src_uri = vm.connect_uri
    if not src_uri:
        src_uri = params.get("connect_uri")
    dest_uri = params.get("virsh_migrate_desturi")
    # Identify easy config. mistakes early
    warning_text = ("Migration VM %s URI %s appears problematic "
                    "this may lead to migration problems. "
                    "Consider specifying vm.connect_uri using "
                    "fully-qualified network-based style.")

    if src_uri.count('///') or src_uri.count('EXAMPLE'):
        logging.warning(warning_text % ('source', src_uri))

    if dest_uri.count('///') or dest_uri.count('EXAMPLE'):
        logging.warning(warning_text % ('destination', dest_uri))

    vm_ref = params.get("vm_ref", vm.name)
    options = params.get("virsh_migrate_options")
    extra = params.get("virsh_migrate_extra")
    delay = int(params.get("virsh_migrate_delay", 10))
    status_error = params.get("status_error", 'no')
    libvirtd_state = params.get("virsh_migrate_libvirtd_state", 'on')
    src_state = params.get("virsh_migrate_src_state", "running")
    dest_xmlfile = ""
    remote_ip = params.get("remote_ip", None)
    remote_password = params.get("remote_password", None)
    local_ip = params.get("local_ip", None)
    migrate_uri = params.get("virsh_migrate_migrateuri", None)
    second_disk = params.get("virsh_migrate_second_disk", 'no')

    #Add migrateuri if exists
    if migrate_uri:
        extra = ("%s --migrateuri=%s" %(extra, migrate_uri))

    #Remote password, ip and local ip must be set
    if not remote_ip or not remote_password or not local_ip:
        raise error.TestNAError("Remote password, ip and local ip must be set.",
                                remote_password, remote_ip, local_ip)

    #Direct migration is supported only for Xen in libvirt
    if options.count("direct") or extra.count("direct"):
        if params.get("driver_type") is not "xen":
            raise error.TestNAError("Direct migration is supported only for "
                                    "Xen in libvirt.")

    exception = False
    try:
        # To migrate you need to have a shared disk between hosts
        utils.run("service nfs restart", verbose=True)
        devices = vm.get_blk_devices()
        nfs_path = os.path.dirname(devices["vda"]["source"])
        disk_image = os.path.basename(devices["vda"]["source"])
        mount_path = "/tmp/libvirt/nfs_share"
        utils.run("exportfs -o rw,no_root_squash *:%s" % nfs_path, verbose=True)

        session = remote.wait_for_login("ssh", remote_ip, "22", "root",
                                        remote_password, "[#$]")

        cmd = "mount"
        cmd_umount = "umount -f %s" % mount_path
        status, output = session.cmd_status_output(cmd)
        if output.count(mount_path):
            status, output = session.cmd_status_output(cmd_umount)
            if status and not output.count("not mounted"):
                raise error.TestError("Fail to umount nfs on remote host '%s'" % output)
        result = utils.run(cmd, verbose=True)
        if result.stdout.count(mount_path):
            utils.run(cmd_umount, verbose=True)

        cmd = "mkdir -p %s" % mount_path
        status, output = session.cmd_status_output(cmd)
        if status:
            raise error.TestError("Fail to create files on remote host '%s'" % output)
        utils.run(cmd, verbose=True)

        cmd = "mount -t nfs %s:%s %s" %(local_ip, nfs_path, mount_path)
        status, output = session.cmd_status_output(cmd)
        if status:
            raise error.TestError("Fail to mount nfs on remote host '%s'" % output)
        utils.run(cmd, verbose=True)

        # Update disk path
        vm.destroy()

        virsh.detach_disk(vm.name, "vda", "--config", debug=True)
        virsh.attach_disk(vm.name, os.path.join(mount_path, disk_image), "vda", "--config --subdriver qcow2 --cache none", debug=True)

        if second_disk == 'yes':
            disk_xml = """
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/tmp/libvirt-shared.img'>
        <seclabel model='selinux' relabel='no'/>
        <seclabel model='dac' relabel='no'/>
      </source>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
      <shareable/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </disk>
            """
            cmd = "touch /tmp/libvirt-shared.img"
            status, output = session.cmd_status_output(cmd)
            utils.run(cmd, verbose=True)

            status, output = session.cmd_status_output("chmod 600 /tmp/libvirt-shared.img")
            utils.run("chmod 666 /tmp/libvirt-shared.img", verbose=True)
            utils.run("chcon system_u:object_r:svirt_image_t:s0 /tmp/libvirt-shared.img", verbose=True)
            utils.run("virsh attach-device %s /dev/stdin --config" % vm.name, stdin=disk_xml, verbose=True)

        vm.start()

        # Confirm VM can be accessed through network.
        vm.wait_for_login()
        vm_ip = vm.get_address()
        s_ping, o_ping = utils_test.ping(vm_ip, count=2, timeout=delay)
        logging.info(o_ping)
        if s_ping != 0:
            raise error.TestError("%s did not respond after %d sec."
                                  % (vm.name, delay))

        # Prepare for --xml.
        logging.debug("Preparing new xml file for --xml option.")
        if options.count("xml") or extra.count("xml"):
            dest_xmlfile = params.get("virsh_migrate_xml", "")
            if dest_xmlfile:
                ret_attach = vm.attach_interface("--type bridge --source "
                                "virbr0 --target tmp-vnet", True, True)
                if not ret_attach:
                    exception = True
                    raise error.TestError("Attaching nic to %s failed." % vm.name)
                ifaces = vm_xml.VMXML.get_net_dev(vm.name)
                new_nic_mac = vm.get_virsh_mac_address(ifaces.index("tmp-vnet"))
                vm_xml_new = vm.get_xml()
                logging.debug("Xml file on source: %s" % vm_xml_new)
                f = codecs.open(dest_xmlfile, 'wb', encoding='utf-8')
                f.write(vm_xml_new)
                f.close()
                if not os.path.exists(dest_xmlfile):
                    exception = True
                    raise error.TestError("Creating %s failed." % dest_xmlfile)

        # Turn VM into certain state.
        logging.debug("Turning %s into certain state." % vm.name)
        if src_state == "paused":
            if vm.is_alive():
                vm.pause()
        elif src_state == "shut off":
            if vm.is_alive():
                if not vm.shutdown():
                    vm.destroy()

        # Turn libvirtd into certain state.
        logging.debug("Turning libvirtd into certain status.")
        if libvirtd_state == "off":
            utils_libvirtd.libvirtd_stop()

        # Test uni-direction migration.
        logging.debug("Doing migration test.")
        if vm_ref != vm_name:
            vm.name = vm_ref    # For vm name error testing.
        ret_migrate = do_migration(delay, vm, dest_uri, options, extra)
        if vm_ref != vm_name:
            vm.name = vm_name

        check_second_disk = True
        if second_disk == 'yes':
            if ret_migrate:
                raise error.TestError("Migration with non-shared disk should fail.")
            vm.verify_kernel_crash()
            g_session = vm.wait_for_login()
            status, g_output = g_session.cmd_status_output("touch /tmp/test.txt")
            logging.debug("status = %s\n output '%s'", status, g_output)
            if status:
                check_second_disk = False
            else:
                g_session.cmd_status_output("rm -rf /tmp/test.txt")
            ret_migrate = True

        # Recover libvirtd state.
        logging.debug("Recovering libvirtd status.")
        if libvirtd_state == "off":
            utils_libvirtd.libvirtd_start()

        # Check vm state on destination.
        logging.debug("Checking %s state on %s." % (vm.name, vm.connect_uri))
        if options.count("dname") or extra.count("dname"):
            vm.name = extra.split()[1].strip()
        check_dest_state = True
        dest_state = params.get("virsh_migrate_dest_state", "running")
        check_dest_state = check_vm_state(vm, dest_state)
        logging.info("Supposed state: %s" % dest_state)
        logging.info("Actual state: %s" % vm.state())

        # Recover VM state.
        logging.debug("Recovering %s state." % vm.name)
        if src_state == "paused":
            vm.resume()
        elif src_state == "shut off":
            vm.start()

        # Checking for --persistent.
        logging.debug("Checking for --persistent option.")
        check_dest_persistent = True
        if options.count("persistent") or extra.count("persistent"):
            if not vm.is_persistent():
                check_dest_persistent = False

        # Checking for --undefinesource.
        logging.debug("Checking for --undefinesource option.")
        check_src_undefine = True
        if options.count("undefinesource") or extra.count("undefinesource"):
            logging.info("Verifying <virsh domstate> DOES return an error."
                         "%s should not exist on %s." % (vm_name, src_uri))
            if virsh.domain_exists(vm_name, uri=src_uri):
                check_src_undefine = False

        # Checking for --dname.
        logging.debug("Checking for --dname option.")
        check_dest_dname = True
        if options.count("dname") or extra.count("dname"):
            dname = extra.split()[1].strip()
            if not virsh.domain_exists(dname, uri=dest_uri):
                check_dest_dname = False

        # Checking for --xml.
        logging.debug("Checking for --xml option.")
        check_dest_xml = True
        if options.count("xml") or extra.count("xml"):
            if dest_xmlfile:
                vm_dest_xml = vm.get_xml()
                logging.info("Xml file on destination: %s" % vm_dest_xml)
                if not re.search(new_nic_mac, vm_dest_xml):
                    check_dest_xml = False

        # Repeat the migration from destination to source.
        if params.get("virsh_migrate_back", "no") == 'yes':
            back_dest_uri = params.get("virsh_migrate_back_desturi", 'default')
            back_options = params.get("virsh_migrate_back_options", 'default')
            back_extra = params.get("virsh_migrate_back_extra", 'default')
            if back_dest_uri == 'default':
                back_dest_uri = src_uri
            if back_options == 'default':
                back_options = options
            if back_extra == 'default':
                back_extra = extra
            ret_migrate = do_migration(delay, vm, back_dest_uri, back_options, back_extra)

    except Exception, detail:
        exception = True
        logging.error("%s: %s" % (detail.__class__, detail))


    # Whatever error occurs, we have to clean up all environment.
    # Make sure vm.connect_uri is the destination uri.
    vm.connect_uri = dest_uri
    if options.count("dname") or extra.count("dname"):
        # Use the VM object to remove
        vm.name = extra.split()[1].strip()
        cleanup_dest(vm, src_uri)
        vm.name = vm_name
    else:
        cleanup_dest(vm, src_uri)

    # Recover source (just in case).
    # vm.connect_uri has been set back to src_uri in cleanup_dest().
    if not virsh.domain_exists(vm_name, uri=src_uri):
        vm.define(vm_xmlfile_bak)
    else:
        #if not vm.shutdown():
        vm.destroy()

    # Cleanup source.
    if os.path.exists(vm_xmlfile_bak):
        os.remove(vm_xmlfile_bak)
        logging.info("%s removed." % vm_xmlfile_bak)
    if os.path.exists(dest_xmlfile):
        os.remove(dest_xmlfile)

    # Cleanup nfs share
    cmd = "umount %s" % mount_path
    status, output = session.cmd_status_output(cmd)
    if status:
        logging.error("Fail to umount nfs on remote host '%s'" % output)
        exception = True
    utils.run(cmd, verbose=True, ignore_status=True)

    cmd = "rm -rf %s" % mount_path
    if status:
        logging.error("Fail to remove mount path on remote host '%s'" % output)
        exception = True
    utils.run(cmd, verbose=True, ignore_status=True)

    utils.run("exportfs -u *:%s" % nfs_path, verbose=True, ignore_status=True)

    # Cleanup disk image
    vm.destroy()

    virsh.detach_disk(vm.name, "vda", "--config", debug=True)
    virsh.attach_disk(vm.name, os.path.join(nfs_path, disk_image), "vda", "--config --subdriver qcow2 --cache none", debug=True)

    if second_disk == 'yes':
        virsh.detach_disk(vm.name, "vdb", "--config", debug=True)
        cmd = "rm -rf /tmp/libvirt-shared.img"
        status, output = session.cmd_status_output(cmd)
        utils.run(cmd, verbose=True, ignore_status=True)

    if exception:
        raise error.TestError("Error occurred. \n%s: %s" % (detail.__class__, detail))

    # Check test result.
    if status_error == 'yes':
        if ret_migrate:
            raise error.TestFail("Migration finished with unexpected status.")
    else:
        if not ret_migrate:
            raise error.TestFail("Migration finished with unexpected status.")
        if not check_dest_state:
            raise error.TestFail("Wrong VM state on destination.")
        if not check_dest_persistent:
            raise error.TestFail("VM is not persistent on destination.")
        if not check_src_undefine:
            raise error.TestFail("VM is not undefined on source.")
        if not check_dest_dname:
            raise error.TestFail("Wrong VM name %s on destination." % dname)
        if not check_dest_xml:
            raise error.TestFail("Wrong xml configuration on destination.")
        if not check_second_disk:
            raise error.TestFail("Source host has read-only disk: '%s'" % g_output)
