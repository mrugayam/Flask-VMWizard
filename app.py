from flask import Flask, jsonify, request, Response
from requests.exceptions import HTTPError
import os
import json
import random, string
import sqlite3
import asyncio
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from azure.identity import AzureCliCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.cli.core import get_default_cli
from azure.mgmt.compute.models import DiskCreateOption
from datetime import timedelta,datetime,timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity,unset_jwt_cookies, jwt_required, JWTManager

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config["JWT_SECRET_KEY"] = "9a73be32-c05a-45a0-a4bd-7e6e5eca64f1"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)
db = SQLAlchemy(app)

def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

# Create connection to the SQLite database
conn = sqlite3.connect('mydatabase.db', check_same_thread=False)
c = conn.cursor()

# Handle errors with method not working
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        res = Response()
        res.headers['X-Content-Type-Options'] = '*'
        return res

#refresh user credentials after a request has been submitted
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response

@app.route('/token', methods=['POST'])
def create_token():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    c.execute('SELECT ID, Role FROM tbl_users WHERE Email = ? AND Password = ?', (email,password))
    user = c.fetchone()
    if user is not None:
        # Retrieve the user's role from the database
        c.execute('SELECT * FROM tbl_roles WHERE ID = ?', (user[1],))
        role = c.fetchone()
        access_token = create_access_token(identity=user[0],additional_claims={'role': role[1]})
        response = {'access_token':access_token}
        return response
    # Return a success message
    else:
        return {'error': 'No user matched!'},401

@app.route("/logout", methods=["POST"])
def logout():    
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

def add_vm(user,name,description,size):
    try:
        # Insert the role's data into the database
        c.execute('INSERT INTO tbl_VMs (User,Name,Description,Size) VALUES (?,?,?,?)', (user,name,description,size))
        conn.commit()
        c.execute('select seq from sqlite_sequence where name="tbl_VMs"')
        vmID = c.fetchone()
        audit(user,"VM",vmID[0],"Added")
        # Return a success message        
        return {'message': 'VM added successfully'}
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

@app.route('/duplicate-vm/<string:name>', methods=["POST"])
@jwt_required()
def check_vm_duplicate(name):
    try:
        vm_name = "P153VM-" + name
        # Insert the role's data into the database
        c.execute('SELECT ID FROM tbl_VMs WHERE Name = ?', (vm_name,))
        vmID = c.fetchone()
        if vmID is not None:
            response = jsonify("Duplicate VM exists- please enter a different postfix")
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        else:
            response = jsonify("")
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})    
        
def audit(user,updatedType,updatedTypeID,action):
    try:
        dt_string = datetime.now()                
        c.execute('INSERT INTO tbl_audits (User,Date,Type,TypeID,Action) VALUES (?,?,?,?,?)', (user,str(dt_string),updatedType,updatedTypeID,action))
        conn.commit()
        # Return a success message
        return {'message': 'Action audited successfully'}
    except Exception as e:
        print(str(e))
        return jsonify({'error': '"An error occurred: ' + str(e)})

def remove_vm(vm_name):
    try:
        c.execute('SELECT * FROM tbl_VMs WHERE Name = ?', (vm_name,))
        vm = c.fetchone()
        if vm is not None:
            vm_id = vm[0]
            c.execute('DELETE FROM tbl_notes WHERE VM = ?', (vm_id,))
            conn.commit()
            c.execute('DELETE FROM tbl_VMs WHERE ID = ?', (vm_id,))
            conn.commit()
            data = request.get_json()
            audit(data['user'],"VM",vm_id,"Deleted")
        # Return a success message
        return {'message': 'vm deleted successfully'}
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

@app.route('/users/<int:user_id>/vms')
@jwt_required()
def get_vms_for_user(user_id):
    try:
        # Retrieve all the virtual machines where the user ID is associated
        c.execute('SELECT * FROM tbl_VMs WHERE User = ?', (user_id,))
        vms = c.fetchall()
        if vms is not None:
        # Convert the virtual machines to a dictionary format
            vm_list = []
            for vm in vms:
                vm_dict = {
                    'ID': vm[0],
                    'User': vm[1],
                    'Description': vm[2],
                    'Name': vm[3],
                    'Size': vm[4],
                }
                vm_list.append(vm_dict)

            # Return the list of virtual machines as a JSON response
            return _corsify_actual_response(jsonify(vm_list))
        else:
            return jsonify({'error': 'no VMs found'})
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
@app.route('/vms')
@jwt_required()
def get_all_vms():
    try:
        # Retrieve all the virtual machines where the user ID is associated
        c.execute('SELECT * FROM tbl_VMs')
        vms = c.fetchall()
        if vms is not None:
        # Convert the virtual machines to a dictionary format
            vm_list = []
            for vm in vms:
                vm_dict = {
                    'ID': vm[0],
                    'User': vm[1],
                    'Description': vm[2],
                    'Name': vm[3],
                    'Size': vm[4],
                }
                vm_list.append(vm_dict)

            # Return the list of virtual machines as a JSON response
            return _corsify_actual_response(jsonify(vm_list))
        else:
            return jsonify({'error': 'no VMs found'})
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

@app.route('/audits')
@jwt_required()
def get_audits():
    try:
        # Retrieve all the virtual machines where the user ID is associated
        c.execute('SELECT * FROM tbl_audits')
        audits = c.fetchall()
        if audits is not None:
        # Convert the virtual machines to a dictionary format
            audit_list = []            
            for audit in audits:
                actionString = str(audit[5]) + ' ' + str(audit[3]) + ' with ID: ' + str(audit[4])
                c.execute('SELECT * FROM tbl_users WHERE ID = ?', (audit[1],))
                user = c.fetchone()
                audit_dict = {
                    'ID': audit[0],
                    'timestamp': audit[2],
                    'action': actionString,
                    'user': user[1]
                }
                audit_list.append(audit_dict)
            # Return the list of virtual machines as a JSON response
            audit_list.reverse()
            return _corsify_actual_response(jsonify(audit_list))
        else:
            return jsonify({})
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
# Define a route for getting user details and their role
@app.route('/users/<int:user_id>')
@jwt_required()
def get_user(user_id):
    try:
        # Retrieve the user's details from the database
        c.execute('SELECT * FROM tbl_users WHERE ID = ?', (user_id,))
        user = c.fetchone()

        if user is not None:
            # Retrieve the user's role from the database
            role_id = user[5]
            c.execute('SELECT * FROM tbl_roles WHERE ID = ?', (role_id,))
            role = c.fetchone()

            # Combine the user and role data into a single dictionary
            user_data = {
                'id': user[0],
                'email': user[1],
                'password': user[2],
                'firstName': user[3],
                'lastName': user[4],
                'role': role[1]
            }
            response = jsonify(user_data)
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        else:
            return jsonify({'error': 'user not found'})
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
# Delete a note
@app.route('/note/<int:note_id>/delete', methods=["POST"])
@jwt_required()
def delete_note(note_id):
    try:
        c.execute('SELECT * FROM tbl_notes WHERE ID = ?', (note_id,))
        note = c.fetchone()
        if note is not None:
            c.execute('DELETE FROM tbl_notes WHERE ID = ?', (note_id,))
            conn.commit()
            data = request.get_json()
            audit(data['user'],"Note",note_id,"Deleted")
        # Return a success message
        return {'message': 'note deleted successfully'}
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
@app.route('/note/create', methods=["POST"])
@jwt_required()
def add_note():
    try:
        data = request.get_json()
        # Insert the note's data into the database
        c.execute('INSERT INTO tbl_notes (User,VM,Description) VALUES (?,?,?)', (data['user'],data['VM'],data['description']))
        conn.commit()
        c.execute('select seq from sqlite_sequence where name="tbl_notes"')
        noteID = c.fetchone()
        audit(data['user'],"Note",noteID[0],"Added")
        # Return a success message
        return {'message': 'Note added successfully'}
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
@app.route('/note/<int:note_id>/update', methods=["PATCH"])
@jwt_required()
def update_note(note_id):
    try:
        data = request.get_json()
        # Insert the note's data into the database
        c.execute('UPDATE tbl_notes SET Description = ? WHERE ID = ?', (data['description'],data['ID']))
        conn.commit()
        data = request.get_json()
        audit(data['user'],"Note",note_id,"Edited")
        # Return a success message
        return {'message': 'Note updated successfully'}
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
# Define a route for getting notes for a given VM
@app.route('/vm/<int:vm_id>/notes')
@jwt_required()
def get_notes(vm_id):
    try:
        # Retrieve the notes from the database
        c.execute('SELECT * FROM tbl_notes WHERE VM = ?', (vm_id,))
        notes = c.fetchall()
        if notes is not None:
            note_list = []
            for note in notes:
                # Retrieve the user's email
                c.execute('SELECT Email FROM tbl_users WHERE ID = ?', (note[1],))
                user = c.fetchone()
                note_dict = {
                    'ID': note[0],
                    'User': user[0],
                    'VM': note[2],
                    'Description': note[3],
                }
                note_list.append(note_dict)
            response = jsonify(note_list)
            response.headers.add('Access-Control-Allow-Origin', '*')
            print(response)
            return response
        else:
            return jsonify([]),200    
    except Exception as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
def az_login():
    try:
        #TODO add these as env variables
        az_cli = get_default_cli()        
        az_cli.invoke(['login', '--service-principal', '-u', os.environ.get('clientid'), '-p', os.environ.get('clientsecret'),'--tenant',os.environ.get('tenantid')])

        # Acquire a credential object using CLI-based authentication.
        credential = AzureCliCredential()

        # Retrieve subscription ID from environment variable.
        subscription_id = "7e4bf01f-7561-4b44-823b-79f8a50f54d8"

        return credential,subscription_id
    except Exception as e:
        print(e)
        return jsonify({'error': '"An error occurred: ' + str(e)})
    
# Stop a VM
@app.route('/vm/<string:vm_name>/stop', methods=['POST'])
@jwt_required()
async def stop_vm(vm_name):
    try:
        # Set up Azure credentials
        credential,subscription_id = az_login()
        compute_client = ComputeManagementClient(credential, subscription_id)        
        
        # Specify the resource group and VM name
        resource_group_name = "P153RG-VMWIZARD"

        # Get the VM object
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Stop the VM
        async_vm_stop = compute_client.virtual_machines.begin_power_off(resource_group_name, vm_name)
        async_vm_stop.wait()        
                
        response = jsonify(vm_name + " has been stopped")
        response.headers.add('Access-Control-Allow-Origin', '*')

        data = request.get_json()
        audit(data['user'],"VM",data['VM'],"Stopped")
        return response
    
    except HTTPError as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

# Start a VM
@app.route('/vm/<string:vm_name>/start', methods=['POST'])
@jwt_required()
async def start_vm(vm_name):
    try:
        # Set up Azure credentials
        credential,subscription_id = az_login()
        compute_client = ComputeManagementClient(credential, subscription_id)

        # Specify the resource group and VM name
        resource_group_name = "P153RG-VMWIZARD"

        # Get the VM object
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Start the VM
        async_vm_start = compute_client.virtual_machines.begin_start(resource_group_name, vm_name)
        async_vm_start.wait()

        data = request.get_json()
        audit(data['user'],"VM",data['VM'],"Started")
        
        response = jsonify(vm_name +" has been started")
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    
    except HTTPError as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

# Restart a VM
@app.route('/vm/<string:vm_name>/restart', methods=['POST'])
@jwt_required()
async def restart_vm(vm_name):
    try:
        # Set up Azure credentials
        credential,subscription_id = az_login()
        compute_client = ComputeManagementClient(credential, subscription_id)

        # Specify the resource group and VM name
        resource_group_name = "P153RG-VMWIZARD"

        # Get the VM object
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Restart the VM
        async_vm_restart = compute_client.virtual_machines.begin_restart(resource_group_name, vm_name)
        async_vm_restart.wait()

        data = request.get_json()
        audit(data['user'],"VM",data['VM'],"Restarted")
        response = jsonify(vm_name + " has been restarted")
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    
    except HTTPError as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})     

# Delete a VM
@app.route('/vm/<string:vm_name>', methods=['DELETE'])
@jwt_required()
async def delete_vm(vm_name):
    try:
        # Set up Azure credentials
        credential,subscription_id = az_login()
        compute_client = ComputeManagementClient(credential, subscription_id)
        # Obtain the management object for networks
        network_client = NetworkManagementClient(credential, subscription_id)
        # Specify the resource group and VM name
        resource_group_name = "P153RG-VMWIZARD"
        nic_name = "P153NIC-" + vm_name[7:]
        pip_name = "P153IP-" + vm_name[7:]        
        disk_name = vm_name + '_OsDisk_'
        # Delete the VM and associated resources
        async_vm_delete = compute_client.virtual_machines.begin_delete(resource_group_name, vm_name)
        async_vm_delete.wait()
        net_del_poller = network_client.network_interfaces.begin_delete(resource_group_name, nic_name)
        net_del_poller.wait()
        ip_del_poller = network_client.public_ip_addresses.begin_delete(resource_group_name, pip_name)
        ip_del_poller.wait()
        disks_list = compute_client.disks.list_by_resource_group(resource_group_name)
        disk_handle_list = []
        async_disk_handle_list = []
        for disk in disks_list:
            if disk_name in disk.name:
                async_disk_delete = compute_client.disks.begin_delete(resource_group_name, disk.name)
                async_disk_handle_list.append(async_disk_delete)
        print("Queued disks will be deleted now...")
        for async_disk_delete in disk_handle_list:
                async_disk_delete.wait()

        remove_vm(vm_name)
        data = request.get_json()
        response = jsonify(vm_name + " has been deleted")
        response.headers.add('Access-Control-Allow-Origin', '*')
        print(response)
        return response
    
    except HTTPError as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

# Define a route for getting user details and their role
@app.route('/vm/create', methods=['POST'])
@jwt_required()
async def create_vm():
    try:
        # Retrieve the data from the request body
        data = request.get_json()

        credential,subscription_id = az_login()

        # Step 1: Get details of the resource group

        # Obtain the management object for resources, using the credentials
        # from the CLI login.
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Constants we need in multiple places: the resource group name and
        # the region in which we provision resources. You can change these
        # values however you want.
        resource_group_name = "P153RG-VMWIZARD"
        location = "ukwest"

        # Get the resource group by name
        resource_group = resource_client.resource_groups.get(resource_group_name)

        # Get the resource group ID
        resource_group_id = resource_group.id

        # A virtual machine requires a network interface client (NIC). A NIC
        # requires a virtual network and subnet along with an IP address.
        # Therefore we must provision these downstream components first, then
        # provision the NIC, after which we can provision the VM.

        # Network and IP address names
        vnet_name = "P153VNet-VMWizard"
        subnet_name = "P153Sub-VMWizard"
        vm_name = "P153VM-" + data['name']
        ip_name = "P153IP-" + data['name']    
        ip_config_name = "P153IPC-" + data['name']
        nic_name = "P153NIC-" + data['name']

        # Obtain the management object for networks
        network_client = NetworkManagementClient(credential, subscription_id)

        # Get details of existing virtual network 
        vnet_result = network_client.virtual_networks.get(resource_group_name, vnet_name)

        # Step 3: Get details of existing subnet
        subnet_result = network_client.subnets.get(resource_group_name, vnet_name, subnet_name)


        # Step 4: Provision an IP address and wait for completion
        poller = network_client.public_ip_addresses.begin_create_or_update(
            resource_group_name,
            ip_name,
            {
                "location": location,
                "sku": {"name": "Standard"},
                "public_ip_allocation_method": "Static",
                "public_ip_address_version": "IPV4",
            },
        )

        ip_address_result = poller.result()

        print(
            f"Provisioned public IP address {ip_address_result.name} \
        with address {ip_address_result.ip_address}"
        )

        # Step 5: Provision the network interface client
        poller = network_client.network_interfaces.begin_create_or_update(
            resource_group_name,
            nic_name,
            {
                "location": location,
                "ip_configurations": [
                    {
                        "name": ip_config_name,
                        "subnet": {"id": subnet_result.id},
                        "public_ip_address": {"id": ip_address_result.id},
                    }
                ],
            },
        )

        nic_result = poller.result()

        print(f"Provisioned network interface client {nic_result.name}")

        # Step 6: Provision the virtual machine

        # Obtain the management object for virtual machines
        compute_client = ComputeManagementClient(credential, subscription_id)

        username = "azureuser"
        password = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(16)])
        vm_size = data['size']
        owner = data['user']
        vm_tags = {
            "Project": "PR00183 – Provisioning Prototype",
            "Service": "PPO",
            "BillingID": "DOP",
            "Owner": owner
        }
        os_disk_name = "P153OS-" + data['name']
        
        print(
            f"Provisioning virtual machine {vm_name}; this operation might take a few minutes.")

        # Provision the VM specifying only minimal arguments, which defaults
        # to an Ubuntu 18.04 VM on a Standard DS1 v2 plan with a public IP address
        # and a default virtual network/subnet.

        poller = compute_client.virtual_machines.begin_create_or_update(
            resource_group_name,
            vm_name,
            {
                "location": location,
                "storage_profile": {
                    "image_reference": {
                        "id": "/subscriptions/7e4bf01f-7561-4b44-823b-79f8a50f54d8/resourceGroups/P153RG-VMWizard/providers/Microsoft.Compute/galleries/P153Images/images/UbuntuImage",                        
                    }
                },
                "hardware_profile": {"vm_size": vm_size},
                "os_profile": {
                    "computer_name": vm_name,
                    "admin_username": username,
                    "admin_password": password,
                },
                "network_profile": {
                    "network_interfaces": [
                        {
                            "id": nic_result.id,
                        }
                    ]
                },
                "tags": vm_tags
            },
        )
        vm_result = poller.result()
        add_vm(owner,vm_name,data['description'],vm_size)
        print(f"Provisioned virtual machine {vm_result.name} with the password {password}")
        response = jsonify("Provisioned virtual machine " + vm_result.name + " with the password: " + password + "\n Please make a note of this password")
        print(response)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except HTTPError as e:
        return jsonify({'error': '"An error occurred: ' + str(e)})

if __name__ == '__main__':
    app.run(debug=True)    
