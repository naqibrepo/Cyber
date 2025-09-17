
===============================================================================
# CLI
```
---------------------------
# VM Management

qm						# qemu manager
man qm
qm list						# list VMs
qm start/shutdown/reboot... <id>		# start/stop VMs
qm reset/stop <id>				# hard reboot/stop
qm config <id>					# VM info

----------------------------
# set VM options

qm config <id>					# VM info
qm set --<optoin>/-<option> <value> <id>
qm set --onboot 0 101				# set the Start at boot to "no"

----------------------------
# Container Commands

same commands as VM:
pct list					# list containers
pct start/shutdown <id>
pct config					# containers info

pct enter <id>					# get inside the container (getting a shell)

pct set --<optoin>/-<option> <value> <id>
```
===============================================================================
# Linux Template
```
---
Create a VM:

OS: No media
No disk

Add cloud init drive
Configure cloud init (regenerate image)

---
Download the cloud image of Linux (wget)

---
qm set <vm id> --serial0 socket --vga serial0		# create a vga console for the vm to see the screen
mv <Linux.img> <Linux.qcow2>				# rename the .img to .qcow2
qemu-img resize <Linux.qcow2> 32G			# resize the image
qm importdisk <vm id> <Linux.qcow2> local-lvm		# import the image as vm disk

---
After importing the disk in cli, we still need to add it on GUI as well
Change boot order
Change start at boot

---
verify settings
Convert to template

```
===============================================================================
# VM Migration
```
vmware-vdiskmanager -r vmname.vmdk -t 0 vmname-single.vmdk


qemu-img convert -f vmdk -O raw vmname-single.vmdk vm-999-disk-0.raw
qm create 999 --name ubuntu-migrated --memory 2048 --net0 virtio,bridge=vmbr0 --ostype l26 --scsihw virtio-scsi-pci
qm set 999 --scsi0 local-lvm:20
dd if=/var/lib/vz/images/999/vm-999-disk-0.raw of=/dev/pve/vm-999-disk-0 bs=4M status=progress


----------------
second option

tar -xvf file.ova
tar -cvf /var/lib/vz/import/migrationTest.ova migrationTest.ovf migrationTest.mf migrationTest-disk1.raw migrationTest-disk2.raw
qm importdisk 101 migrationTest-disk2.raw local-lvm 



```
