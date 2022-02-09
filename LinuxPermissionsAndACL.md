# Lab 6 - Linux permissions and ACL

Through this exercise we will learn how to manipulate accounts on linux including access control.

### First we create a new user

1. To see the current user id we can use the `id` command
2. We need to check if we are in the `sudo` group, we can do this with the `groups` command
3. Create a new user

```bash
sudo adduser alice
```

1. And now let us login as the new user

```bash
su - alice
```

1. Now lets exit to the sudo shell with `exit` command and create another user

```bash
sudo adduser bob
```

### Basic access rights to files

1. Let us login as the user `alice`

```bash
su - alice
```

1. Create a new folder in the `home` directory and a file within it

```bash
cd # to navigate to home folder
mkdir srp
cd srp
echo "Some random text" > security.txt
```

1. Now we will list the rights to the given file using some of the next commands

```bash
ls -l .
ls -l srp
ls -l srp/security.txt

getfacl srp
getfacl srp/security.txt
getfacl -t srp/security.txt
```

1. Using command `chmod` we can modify access rights to the given file

```bash
# Remove (u)ser (r)ead permission
chmod u-r security.txt

# Add (u)ser (r)ead permission
chmod u+r security.txt

# Remove both (u)ser and (g)roup (w)rite permission
chmod ug-w security.txt

# Add (u)ser (w)rite and remove (g)roup (r)ead permission
chmod u+w,g-r security.txt

# Add (u)ser (r)read, (w)rite permissions and remove e(x)ecute permpission
chmod u=rw security.txt
```

1. We can now experiment changing the rights to the file and accessing it from one or the other user we created
    1. IE: we can remove the Alices’ rights to write in the file and check to see if we can write in it, we shouldn’t be able to, also if we add the write rights to `other` users we can see that Bob can write inside the file
2. We can also add users to a specific group that has access to the given file and with this way the specific user can access the files this is done with `usermod` command (with sudo privileges) in the following way

```bash
usermod -aG <group name> user_name
```

### Access rights using ACL-s

To inspect and modify ACLs we can use the commands `getfacl` and `setfacl`

1. We can now use a different approach to give the user `bob` rights over the created file. To do this we can use ACLs in the next way

```bash
# 1. Read/record current permissions defined on the file
getfacl security.txt

# 2. Add (u)ser bob to the ACL list of the file with (r)ead premission
setfacl -m u:bob:r security.txt

# 3. Check the updated permissions defined on the file
getfacl security.txt

# 4. Login as bob, navigate to the file and try to read its content
cat security.txt
```

1. We can also remove the entry from the ACL in the next way

```bash
# Removing one entry from ACL
setfacl -x u:bob security.txt

# Removing the complete ACL
setfacl -b security.txt
```

### Linux processes and access control

Linux processes are programs which are executing in a specific address space. We can list the currently active processes using the command `ps -ef` . By doing this we can notice that each process has a specific UID and PID.

1. Let us create a python script

```bash
import os

print('Real (R), effective (E) and saved (S) UIDs:') 
print(os.getresuid())

with open('/home/alice/srp/security.txt', 'r') as f:
    print(f.read())
```

1. Make sure that user `bob` doesn’t have access rights to the create file
2. Run the file as `alice` and as `bob`
3. We can see that running it as `alice` the script runs with no issues. Running it as user `bob` we can see that the script fails because the process was run by `bob` and `bob` doesn’t have access rights to the file created by `alice` which translates to the process (python script) ran by him