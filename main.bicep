@description('main template')
param location string = resourceGroup().location
param vmSize string = 'Standard_B1ms'
param adminUsername string = 'azureuser'
@secure()
param adminPassword string
param wordpressImage string = 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest'
param tagCourse string = 'test'

// Read users from local CSV (must be next to this bicep file)
var usersCsv = loadTextContent('users.csv')

/* ------------ globalna mreža i jump-host ------------ */

resource vnet 'Microsoft.Network/virtualNetworks@2022-05-01' = {
  name: 'course-vnet'
  location: location
  tags: { course: tagCourse }
  properties: {
    addressSpace: { addressPrefixes: [ '10.20.0.0/16' ] }
  }
}

resource jumpSubnet 'Microsoft.Network/virtualNetworks/subnets@2022-05-01' = {
  parent: vnet
  name: 'jump-subnet'
  properties: {
    addressPrefix: '10.20.0.0/24'
  }
}

resource jumpNSG 'Microsoft.Network/networkSecurityGroups@2022-05-01' = {
  name: 'jump-nsg'
  location: location
  tags: { course: tagCourse }
  properties: {
    securityRules: [
      {
        name: 'SSH'
        properties: {
          access: 'Allow'
          direction: 'Inbound'
          priority: 100
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource jumpPublicIP 'Microsoft.Network/publicIPAddresses@2022-05-01' = {
  name: 'jump-pip'
  location: location
  tags: { course: tagCourse }
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource jumpNIC 'Microsoft.Network/networkInterfaces@2022-05-01' = {
  name: 'jump-nic'
  location: location
  tags: { course: tagCourse }
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: jumpSubnet.id }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: jumpPublicIP.id }
        }
      }
    ]
    networkSecurityGroup: { id: jumpNSG.id }
  }
}

resource jumpVM 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'jump-host'
  location: location
  tags: { course: tagCourse }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: 'jump-host'
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    networkProfile: { networkInterfaces: [ { id: jumpNIC.id } ] }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts'
        version: 'latest'
      }
      osDisk: { createOption: 'FromImage', name: 'jump-osdisk' }
    }
  }
}

/* ------------ managed identity for deploymentScripts ------------ */

resource dsUami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'ds-uami'
  location: location
}

var contributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b24988ac-6180-42a0-ab88-20f7382dd24c' 
)

resource dsUamiContrib 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, dsUami.name, contributorRoleId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: contributorRoleId
    principalId: dsUami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

/* ------------ users from CSV via a single deployment script ------------ */


resource usersScript 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'deploy-users'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${dsUami.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.75.0' // if deployment says "unsupported version", try '2.75.0' or '2.74.0'
    scriptContent: '''
#!/usr/bin/env bash
set -euo pipefail

# Login with UAMI and select subscription
az login --identity --allow-no-subscriptions --output none
if [[ -n "${SUBSCRIPTION_ID:-}" ]]; then
  for i in {1..18}; do
    if az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors 2>/dev/null; then
      break
    fi
    echo "Waiting for RBAC to propagate..."
    sleep 10
  done
fi


# Inputs from env
SUBNET_ID="${SUBNET_ID}"
LOCATION="${LOCATION}"
VM_SIZE="${VM_SIZE}"
ADMIN_USERNAME="${ADMIN_USERNAME}"
ADMIN_PASSWORD="${ADMIN_PASSWORD}"
TAG_COURSE="${TAG_COURSE}"
IMAGE_REFERENCE="${IMAGE_REFERENCE}"
RESOURCE_GROUP="${RESOURCE_GROUP}"

# Parse CSV (header: mail,role)
echo "$USERS_CSV" | tail -n +2 | while IFS=',' read -r mail role; do
  [[ -z "$mail" ]] && continue
  name="${mail%@*}"

  for j in 1; do
    vmName="${name}-vm${j}"

    az vm create \
      --name "$vmName" \
      --resource-group "$RESOURCE_GROUP" \
      --image "$IMAGE_REFERENCE" \
      --admin-username "$ADMIN_USERNAME" \
      --admin-password "$ADMIN_PASSWORD" \
      --size "$VM_SIZE" \
      --subnet "$SUBNET_ID" \
      --public-ip-address "" \
      --nsg "" \
      --tags "course=$TAG_COURSE" "owner=$mail" "role=$role" \
      --only-show-errors --output none

    for k in 1 2; do
      diskName="${vmName}-disk${k}"
      az disk create --name "$diskName" --size-gb 5 --resource-group "$RESOURCE_GROUP" \
        --tags "course=$TAG_COURSE" "owner=$mail" "role=$role" --only-show-errors --output none
      az vm disk attach --name "$diskName" --vm-name "$vmName" --resource-group "$RESOURCE_GROUP" \
        --only-show-errors --output none
    done
  done
done
'''
    environmentVariables: [
      { name: 'USERS_CSV',       value: usersCsv }
      { name: 'SUBNET_ID',       value: jumpSubnet.id }
      { name: 'LOCATION',        value: location }
      { name: 'VM_SIZE',         value: vmSize }
      { name: 'ADMIN_USERNAME',  value: adminUsername }
      { name: 'ADMIN_PASSWORD',  secureValue: adminPassword }
      { name: 'TAG_COURSE',      value: tagCourse }
      { name: 'IMAGE_REFERENCE', value: wordpressImage }
      { name: 'RESOURCE_GROUP',  value: resourceGroup().name }
      { name: 'SUBSCRIPTION_ID', value: subscription().subscriptionId }
    ]
    retentionInterval: 'P1D'
    cleanupPreference: 'OnSuccess'
  }
  dependsOn: [ dsUamiContrib ]
}
