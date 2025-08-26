@description('Glavni Bicep template za web‑dev tečaj')
param location string = resourceGroup().location
param users array                                    // npr. [ { name:'marko.maric', role:'instruktor' }, ... ]
param vmSize string = 'Standard_B1ms'
param adminUsername string = 'azureuser'
@secure()
param adminPassword string
param wordpressImage string = 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest'
param tagCourse string = 'test'

/* ------------ globalna mreža i jump-host ------------ */

resource vnet 'Microsoft.Network/virtualNetworks@2022-05-01' = {
  name: 'course-vnet'
  location: location
  tags: { course: tagCourse }
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }
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
          subnet: {
            id: jumpSubnet.id
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: jumpPublicIP.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: jumpNSG.id
    }
  }
}

resource jumpVM 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'jump-host'
  location: location
  tags: { course: tagCourse }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: 'jump-host'
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    networkProfile: {
      networkInterfaces: [
        { id: jumpNIC.id }
      ]
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        name: 'jump-osdisk'
      }
    }
  }
}

/* ------------ per-user deployment ------------ */

var subnetPrefixBase = '10.20'
var subnetIndex = 1

resource userDeployments 'Microsoft.Resources/deploymentScripts@2019-10-01-preview' = [for (user, i) in users: {
  name: 'deploy-${user.name}'
  location: location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
  }
  properties: {
    azPowerShellVersion: '9.4'
    scriptContent: '''
param($subnet, $user, $location, $vmSize, $adminUsername, $adminPassword, $tagCourse, $imageReference)

for ($j = 1; $j -le 4; $j++) {
  $vmName = "$($user.name)-vm$j"

  az vm create `
    --name $vmName `
    --resource-group $env:AZURE_RESOURCE_GROUP `
    --image $imageReference `
    --admin-username $adminUsername `
    --admin-password $adminPassword `
    --size $vmSize `
    --subnet $subnet `
    --public-ip-address "" `
    --nsg "" `
    --tags course=$tagCourse `
    --output none

  for ($k = 1; $k -le 2; $k++) {
    $diskName = "$vmName-disk$k"
    az disk create --name $diskName --size-gb 5 --resource-group $env:AZURE_RESOURCE_GROUP --tags course=$tagCourse --output none
    az vm disk attach --name $diskName --vm-name $vmName --resource-group $env:AZURE_RESOURCE_GROUP --output none
  }
}
'''
    arguments: format(
      '-subnet "{0}.{1}" -user {2} -location {3} -vmSize {4} -adminUsername {5} -adminPassword {6} -tagCourse {7} -imageReference "{8}"',
      subnetPrefixBase,
      subnetIndex + i,
      json(user),
      location,
      vmSize,
      adminUsername,
      adminPassword,
      tagCourse,
      wordpressImage
    )
    retentionInterval: 'P1D'
  }
}]
