# cnc41-sh-demo-pkg


1) You can get the sample heuristics package from CNC UI by going to Administration->Heuristics Package and select system and export.

2) The custom folder is the modified version that can be tarred and then imported - see next step.

tar --disable-copyfile -cvzf import-hp.tar.gz custom
# This still gives the following errors when untarred
# tar: Ignoring unknown extended header keyword 'LIBARCHIVE.xattr.com.apple.quarantine'
# use the following for that (not confirmed)

tar --no-xattrs --disable-copyfile -cvzf import-hp.tar.gz custom

3) Import by going to CNC UI and Administration->Heuristics Package, custom and then import.

4) Fix any errors.




