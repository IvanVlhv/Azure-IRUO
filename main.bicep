@description('Lokacija resursa')
param location string = resourceGroup().location

@description('tip VM-a')
param vmSize string = 'Standard_B1s'

@description('jump host tip VM-a')
param jumpVmSize string = 'Standard_B1s'

@description('Admin korisnik')
param adminUsername string = 'azureuser'

@secure()
@description('Admin lozinka (i za ostale račune lozinka)')
param adminPassword string

@description('Ubuntu slika')
param ubuntuImage string = 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest'

@description('Tag tečaja')
param tagCourse string = 'test'

@minValue(0)
@description('Broj instruktorskih VM-ova')
param instructorVmCount int = 1

@minValue(1)
@description('Broj studentskih VM-ova')
param perUserVmCount int = 1

@description('Ako false pri deploy ugasi VM-ove')
param powerOn bool = true

@description('Opcionalno: GUID grupe INSTRUKTORA')
param instructorsGroupObjectId string = ''

@description('GUID grupe STUDENATA')
param studentsGroupObjectId string = ''

@description('SKU dodatnih diskova')
param diskSku string = 'Standard_LRS'

var usersCsv = loadTextContent('users.csv') 

// HUB - instuktorska mreža
resource hubVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'hub-vnet'
  location: location
  tags: { course: tagCourse }
  properties: {
    addressSpace: { addressPrefixes: [ '10.90.0.0/16' ] }
    subnets: [
      {
        name: 'instructor-subnet'
        properties: { addressPrefix: '10.90.1.0/24' }
      }
    ]
  }
}

//  Managed Identity 
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'deploy-uami'
  location: location
  tags: { course: tagCourse }
}

var roleContributor   = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b24988ac-6180-42a0-ab88-20f7382dd24c')
var roleUAA           = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','18d7d88d-d35e-4fb5-a5c3-7773c20a72d9')

resource uamiContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, uami.name, 'contrib')
  scope: resourceGroup()
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleContributor
  }
}
resource uamiUaa 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, uami.name, 'uaa')
  scope: resourceGroup()
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleUAA
  }
}

// Glavna deployment skripta 
resource deployAll 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'course-deploy'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${uami.id}': {} }
  }
  properties: {
    azCliVersion: '2.75.0'
    retentionInterval: 'P1D'
    cleanupPreference: 'OnSuccess'
    environmentVariables: [
      { name: 'USERS_CSV',                 value: usersCsv }
      { name: 'LOCATION',                  value: location }
      { name: 'UBUNTU_IMAGE',              value: ubuntuImage }
      { name: 'VM_SIZE',                   value: vmSize }
      { name: 'JUMP_VM_SIZE',              value: jumpVmSize }
      { name: 'ADMIN_USERNAME',            value: adminUsername }
      { name: 'ADMIN_PASSWORD',            secureValue: adminPassword }
      { name: 'TAG_COURSE',                value: tagCourse }
      { name: 'DISK_SKU',                  value: diskSku }
      { name: 'RESOURCE_GROUP',            value: resourceGroup().name }
      { name: 'SUBSCRIPTION_ID',           value: subscription().subscriptionId }
      { name: 'HUB_VNET_ID',               value: hubVnet.id }
      { name: 'HUB_INSTR_CIDR',            value: '10.90.1.0/24' }
      { name: 'INSTRUCTOR_VM_COUNT',       value: string(instructorVmCount) }
      { name: 'PER_USER_VM_COUNT',         value: string(perUserVmCount) }
      { name: 'POWER_ON',                  value: powerOn ? 'true' : 'false' }
      { name: 'INSTRUCTORS_GROUP_OID',     value: instructorsGroupObjectId }
      { name: 'STUDENTS_GROUP_OID',        value: studentsGroupObjectId }
      { name: 'STORAGE_SUFFIX',            value: environment().suffixes.storage }
    ]
    scriptContent: '''
#!/usr/bin/env bash
set -uo pipefail
trap 'echo "[WARN] step failed at line ${LINENO}, continuing..."' ERR
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

az config set core.display_region_identified=false --only-show-errors 1>/dev/null || true
az login --identity --allow-no-subscriptions --only-show-errors 1>/dev/null
az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors

RG="$RESOURCE_GROUP"

# helpers 
safe() { echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c1-20; }
addr_block(){ local i="$1"; echo "10.91.${i}.0/24"; }
app_prefix(){ local i="$1"; echo "10.91.${i}.0/25"; }
jump_prefix(){ local i="$1"; echo "10.91.${i}.128/26"; }

# $1: storage account; $2: blob SAS (?..); $3: file SAS (?..); $4: student username; $5: output path
write_wp_cloud_init(){
  local sa="$1" blobsas="$2" filesas="$3" studuser="$4" out="$5"
  cat > "$out" <<'CLOUD'
#cloud-config
package_update: true
packages:
  - nginx
  - php-fpm
  - php-xml
  - php-curl
  - php-zip
  - php-mbstring
  - php-gd
  - php-sqlite3
  - unzip
write_files:
  - path: /etc/nginx/sites-available/default
    content: |
      server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
        index index.php index.html index.htm;
        server_name _;
        location / { try_files $uri $uri/ /index.php?$args; }
        location ~ \.php$ {
          include snippets/fastcgi-php.conf;
          fastcgi_pass unix:/run/php/php-fpm.sock;
        }
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
          expires max; log_not_found off;
        }
      }
runcmd:
  - useradd -m __STUDUSER__ || true
  - bash -lc 'echo "__STUDUSER__:__PASS__" | chpasswd'
  - usermod -aG sudo __STUDUSER__ || true
  - bash -lc 'PHP_SOCK=$(ls /run/php/php*-fpm.sock | head -n1 || echo /run/php/php8.1-fpm.sock); sed -ri "s#fastcgi_pass unix:.*fpm\.sock;#fastcgi_pass unix:${PHP_SOCK};#" /etc/nginx/sites-available/default'
  - curl -L https://wordpress.org/latest.tar.gz -o /tmp/wp.tgz
  - mkdir -p /var/www/html
  - tar -xzf /tmp/wp.tgz -C /var/www/html --strip-components=1
  - curl -L https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip -o /tmp/sqlite.zip
  - unzip -o /tmp/sqlite.zip -d /var/www/html/wp-content/plugins
  - cp /var/www/html/wp-content/plugins/sqlite-database-integration/db.copy /var/www/html/wp-content/db.php
  - chown -R www-data:www-data /var/www/html
  - systemctl enable --now php*-fpm || systemctl enable --now php8.1-fpm || true
  - systemctl restart nginx
CLOUD
  # lab mode: bez storage mount-a, lokalni wp-content
  sed -i "s|__STUDUSER__|${studuser}|g" "$out"
  sed -i "s|__PASS__|${ADMIN_PASSWORD}|g" "$out"
}

write_jump_cloud_init(){
  local studuser="$1" out="$2"
  cat > "$out" <<'CLOUD'
#cloud-config
package_update: true
packages: [ htop, tmux ]
runcmd:
  - useradd -m __STUDUSER__ || true
  - bash -lc 'echo "__STUDUSER__:__PASS__" | chpasswd'
  - usermod -aG sudo __STUDUSER__ || true
CLOUD
  sed -i "s|__STUDUSER__|${studuser}|g" "$out"
  sed -i "s|__PASS__|${ADMIN_PASSWORD}|g" "$out"
}

create_student_nsgs(){
  local nsg_app="$1" nsg_jump="$2" jump_cidr="$3" instr_cidr="$4"
  az network nsg create -g "$RG" -n "$nsg_app" --only-show-errors 1>/dev/null
  az network nsg create -g "$RG" -n "$nsg_jump" --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-SSH-From-Jump \
    --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$jump_cidr" --destination-port-ranges 22 --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-HTTP-From-Jump \
    --priority 110 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$jump_cidr" --destination-port-ranges 80 --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-SSH-From-Instructor \
    --priority 120 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$instr_cidr" --destination-port-ranges 22 --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-HTTP-From-Instructor \
    --priority 130 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$instr_cidr" --destination-port-ranges 80 --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-AzureLB-Probe \
    --priority 140 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes AzureLoadBalancer --destination-port-ranges '*' --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg_jump" -n Allow-SSH-Internet \
    --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes '*' --destination-port-ranges 22 --only-show-errors 1>/dev/null
}

# Instruktorski VM-ovi u HUB-u 
if [[ "${INSTRUCTOR_VM_COUNT}" -gt 0 ]]; then
  for i in $(seq 1 "${INSTRUCTOR_VM_COUNT}"); do
    az vm create -g "$RG" -n "instructor-vm${i}" \
      --image "$UBUNTU_IMAGE" --size "$VM_SIZE" \
      --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
      --vnet-name "$(basename "$HUB_VNET_ID")" --subnet "instructor-subnet" \
      --public-ip-address "" --nsg "" --tags course="$TAG_COURSE" role="instructor" --only-show-errors 1>/dev/null
    for d in 1 2; do
      az disk create -g "$RG" -n "instructor-vm${i}-disk${d}" --size-gb 5 --sku "$DISK_SKU" --only-show-errors 1>/dev/null
      az vm disk attach -g "$RG" --vm-name "instructor-vm${i}" --name "instructor-vm${i}-disk${d}" --only-show-errors 1>/dev/null
    done
    az vm boot-diagnostics enable -g "$RG" -n "instructor-vm${i}" --only-show-errors 1>/dev/null
    [[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "instructor-vm${i}" --only-show-errors 1>/dev/null || true
  done
fi

# RBAC za instruktorsku grupu
if [[ -n "${INSTRUCTORS_GROUP_OID:-}" ]]; then
  az role assignment create --assignee-object-id "$INSTRUCTORS_GROUP_OID" \
    --assignee-principal-type Group --role "Virtual Machine Contributor" \
    --scope "$(az group show -n "$RG" --query id -o tsv)" --only-show-errors 1>/dev/null || true
fi

idx=1
while IFS=',' read -r mail role; do
  [[ -z "${mail:-}" ]] && continue
  [[ "$mail" == "mail" ]] && continue  # preskoči header
  role_lc="$(echo "$role" | tr '[:upper:]' '[:lower:]')"
  [[ "$role_lc" != "student" ]] && continue

  name="$(safe "${mail%@*}")"      # npr. jsabol2
  studuser="stud_${name}"           # OS account na VM-ovima

  vnet="stu-${name}-vnet"
  appSubnet="app-subnet"
  jumpSubnet="jump-subnet"
  nsgApp="stu-${name}-app-nsg"
  nsgJump="stu-${name}-jump-nsg"
  natPip="stu-${name}-natpip"
  natGw="stu-${name}-nat"
  lb="stu-${name}-ilb"; fe="fe"; be="be"
  sa="sa$(echo ${name} | tr -cd 'a-z0-9' | cut -c1-10)$(date +%H%M%S | tr -cd '0-9' | tail -c6)"; sa="${sa:0:23}"

  vnetCidr="$(addr_block $idx)"
  appCidr="$(app_prefix $idx)"
  jumpCidr="$(jump_prefix $idx)"
  idx=$((idx+1))

  log "Student $mail -> $name  VNet:$vnet ($vnetCidr) app:$appCidr jump:$jumpCidr"

  # VNet + subneti
  az network vnet create -g "$RG" -n "$vnet" --address-prefixes "$vnetCidr" \
    --subnet-name "$appSubnet" --subnet-prefixes "$appCidr" --only-show-errors 1>/dev/null
  az network vnet subnet create -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --address-prefixes "$jumpCidr" --only-show-errors 1>/dev/null

  # NSG pravila
  create_student_nsgs "$nsgApp" "$nsgJump" "$jumpCidr" "$HUB_INSTR_CIDR"
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet" --network-security-group "$nsgApp" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --network-security-group "$nsgJump" --only-show-errors 1>/dev/null

  # NAT Gateway (egress) na oba subneta
  az network public-ip create -g "$RG" -n "$natPip" --sku Standard --allocation-method Static --only-show-errors 1>/dev/null
  az network nat gateway create -g "$RG" -n "$natGw" --public-ip-addresses "$natPip" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet"  --nat-gateway "$natGw" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --nat-gateway "$natGw" --only-show-errors 1>/dev/null

  # Storage (Blob+Files) + SAS
  az storage account create -g "$RG" -n "$sa" -l "$LOCATION" --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 --https-only true --allow-blob-public-access false --only-show-errors 1>/dev/null
  key=$(az storage account keys list -g "$RG" -n "$sa" --query "[0].value" -o tsv)
  az storage container create --account-name "$sa" --name obj --account-key "$key" --only-show-errors 1>/dev/null
  az storage share create --account-name "$sa" --name files --account-key "$key" --only-show-errors 1>/dev/null
  expiry=$(date -u -d "+365 days" +"%Y-%m-%dT%H:%MZ" 2>/dev/null || date -u -v+365d +"%Y-%m-%dT%H:%MZ")
  blobSas="$(az storage container generate-sas --account-name "$sa" --name obj --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"
  fileSas="$(az storage share generate-sas --account-name "$sa" --name files --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"

  # Internal Load Balancer (privatni)
  cidr_no_mask="${appCidr%/*}"
  IFS='.' read -r o1 o2 o3 o4 <<< "$cidr_no_mask"
  ILB_IP="${o1}.${o2}.${o3}.10"
  az network lb create -g "$RG" -n "$lb" --sku Standard \
    --vnet-name "$vnet" --subnet "$appSubnet" --frontend-ip-name "$fe" --backend-pool-name "$be" \
    --private-ip-address "$ILB_IP" --only-show-errors 1>/dev/null
  az network lb probe create -g "$RG" --lb-name "$lb" -n http --protocol tcp --port 80 --only-show-errors 1>/dev/null
  az network lb rule create -g "$RG" --lb-name "$lb" -n http80 --protocol Tcp --frontend-port 80 --backend-port 80 \
    --frontend-ip-name "$fe" --backend-pool-name "$be" --probe-name http --idle-timeout 4 --only-show-errors 1>/dev/null
  beId=$(az network lb address-pool show -g "$RG" --lb-name "$lb" -n "$be" --query id -o tsv)

  # Jump host (po studentu, jedini s javnim IP-om)
  jci="/tmp/${name}-jump-init.yml"; write_jump_cloud_init "$studuser" "$jci"
  az vm create -g "$RG" -n "jump-${name}" \
    --image "$UBUNTU_IMAGE" --size "$JUMP_VM_SIZE" \
    --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
    --vnet-name "$vnet" --subnet "$jumpSubnet" \
    --public-ip-address "jump-${name}-pip" --nsg "" --custom-data "$jci" \
    --tags course="$TAG_COURSE" owner="$mail" role="student-jump" --only-show-errors 1>/dev/null
  az vm boot-diagnostics enable -g "$RG" -n "jump-${name}" --only-show-errors 1>/dev/null
  [[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "jump-${name}" --only-show-errors 1>/dev/null || true

  # WP VM-ovi + diskovi + dodavanje u LB backend
  for j in $(seq 1 "${PER_USER_VM_COUNT}"); do
    vm="wp-${name}-${j}"
    ci="/tmp/${name}-wp-${j}.yml"; write_wp_cloud_init "$sa" "?${blobSas}" "?${fileSas}" "$studuser" "$ci"
    az vm create -g "$RG" -n "$vm" \
      --image "$UBUNTU_IMAGE" --size "$VM_SIZE" \
      --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
      --vnet-name "$vnet" --subnet "$appSubnet" \
      --public-ip-address "" --nsg "" --custom-data "$ci" \
      --tags course="$TAG_COURSE" owner="$mail" role="student-wp" --only-show-errors 1>/dev/null
    for d in 1 2; do
      az disk create -g "$RG" -n "${vm}-disk${d}" --size-gb 5 --sku "$DISK_SKU" --only-show-errors 1>/dev/null
      az vm disk attach -g "$RG" --vm-name "$vm" --name "${vm}-disk${d}" --only-show-errors 1>/dev/null
    done
    az vm boot-diagnostics enable -g "$RG" -n "$vm" --only-show-errors 1>/dev/null

    nicId=$(az vm show -g "$RG" -n "$vm" --query "networkProfile.networkInterfaces[0].id" -o tsv)
    nicName=$(basename "$nicId")
    az network nic ip-config address-pool add -g "$RG" --nic-name "$nicName" --ip-config-name "ipconfig1" --address-pool "$beId" --only-show-errors 1>/dev/null

    [[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "$vm" --only-show-errors 1>/dev/null || true
  done

  # Peering HUB <-> STUDENT
  az network vnet peering create -g "$RG" -n "hubTo-${name}" \
    --vnet-name "$(basename "$HUB_VNET_ID")" --remote-vnet "$vnet" \
    --allow-vnet-access --only-show-errors 1>/dev/null || true
  az network vnet peering create -g "$RG" -n "${name}-to-hub" \
    --vnet-name "$vnet" --remote-vnet "$(basename "$HUB_VNET_ID")" \
    --allow-vnet-access --only-show-errors 1>/dev/null || true

done < <(echo "$USERS_CSV")

log "Deployment done."

exit 0
'''
  }
  dependsOn: [ uamiContributor, uamiUaa ]
}
