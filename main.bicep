@description('Lokacija resursa')
param location string = resourceGroup().location

@description('VM veličina (1 vCPU/1GB: Standard_B1s idealno)')
param vmSize string = 'Standard_B1s'

@description('Veličina jump hosta')
param jumpVmSize string = 'Standard_B1s'

@description('Admin korisnik')
param adminUsername string = 'azureuser'

@secure()
@description('Admin lozinka')
param adminPassword string

@description('Ubuntu slika (22.04 LTS)')
param ubuntuImage string = 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest'

@description('Tag tečaja')
param tagCourse string = 'cloudlearn'

@minValue(0)
@description('BROJ instruktorskih VM-ova (3.2) — default 0 zbog kvote')
param instructorVmCount int = 1

@minValue(1)
@description('BROJ WordPress VM-ova po studentu (3.2) — default 1 radi kvote')
param perUserVmCount int = 1

@description('Ako false: odmah deallocate nove VM-ove (štedi vCPU kvotu)')
param powerOn bool = true

@description('Opcionalno: GUID grupe INSTRUKTORA (Entra ID Object ID). Ako zadano, grupa dobiva VM Contributor na RG-u.')
param instructorsGroupObjectId string = ''

@description('Opcionalno: GUID grupe STUDENATA. Ako zadano, grupa dobiva VM Operator + Serial Console na SVE studentske VM-ove (kompromis za 3.4).')
param studentsGroupObjectId string = ''

@description('SKU dodatnih diskova')
param diskSku string = 'Standard_LRS'

var usersCsv = loadTextContent('users.csv') // mail,role

// ---------- HUB (instruktorska mreža + SHARED JUMP HOST) ----------
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

// NSG za jump-host NIC (otvara SSH s Interneta SAMO za taj VM)
resource jumpHostNsg 'Microsoft.Network/networkSecurityGroups@2022-05-01' = {
  name: 'jump-host-nsg'
  location: location
  tags: { course: tagCourse }
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Internet'
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

// ---------- Managed Identity za skriptu ----------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'deploy-uami'
  location: location
  tags: { course: tagCourse }
}

var roleContributor   = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b24988ac-6180-42a0-ab88-20f7382dd24c')
var roleUAA           = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','18d7d88d-d35e-4fb5-a5c3-7773c20a72d9')
var roleVmContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','9980e02c-c2be-4d73-94e8-173b1dc7cf3c')
var roleVmOperator    = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','d5a91429-5739-47e2-a06b-3470a27159e7')
var roleVmSerial      = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','cdaa44e7-1d04-46b8-a2cd-97b88bdbd527')

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

// ---------- Glavna deployment skripta (Azure CLI) ----------
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
      { name: 'JUMP_HOST_NSG_ID',          value: jumpHostNsg.id }
      // Izbjegnemo hard-coded DNS suffix: koristimo environment().suffixes.storage
      { name: 'STORAGE_SUFFIX',            value: environment().suffixes.storage }
    ]
    scriptContent: '''
#!/usr/bin/env bash
set -euo pipefail
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

az config set core.display_region_identified=false --only-show-errors 1>/dev/null || true
az login --identity --allow-no-subscriptions --only-show-errors 1>/dev/null
az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors

RG="$RESOURCE_GROUP"

safe() { echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c1-20; }
addr_block(){ local i="$1"; echo "10.91.${i}.0/24"; }
app_prefix(){ local i="$1"; echo "10.91.${i}.0/25"; }

write_cloud_init(){
  local sa="$1" blobsas="$2" filesas="$3" out="$4"
  cat > "$out" <<'CLOUD'
#cloud-config
package_update: true
packages: [ nginx, php-fpm, php-xml, php-curl, php-zip, php-mbstring, php-gd, php-sqlite3, unzip, cifs-utils, blobfuse2, keyutils ]
write_files:
  - path: /etc/fuse.conf
    content: |
      user_allow_other
    append: true
  - path: /etc/nginx/sites-available/default
    content: |
      server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html; index index.php index.html index.htm; server_name _;
        location / { try_files $uri $uri/ /index.php?$args; }
        location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php-fpm.sock; }
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ { expires max; log_not_found off; }
      }
  - path: /etc/blobfuse2.yaml
    content: |
      logging: { type: syslog }
      components: [ libfuse ]
      containers:
        - name: obj
          account-name: __SA__
          container: obj
          sas: "__BLOB_SAS__"
runcmd:
  - mkdir -p /mnt/objstore /mnt/afiles /var/www/html
  - sed -i 's/#user_allow_other/user_allow_other/' /etc/fuse.conf || true
  - blobfuse2 mount /mnt/objstore --config-file=/etc/blobfuse2.yaml --allow-other || true
  - mount -t cifs //__SA__.file.__STOR_SUFFIX__/files /mnt/afiles -o vers=3.0,username=AZURE\\__SA__,password=__FILE_SAS__,dir_mode=0775,file_mode=0664,serverino,nofail
  - curl -L https://wordpress.org/latest.tar.gz -o /tmp/wp.tgz
  - tar -xzf /tmp/wp.tgz -C /var/www/html --strip-components=1
  - mkdir -p /mnt/afiles/wp-content; rsync -a /var/www/html/wp-content/ /mnt/afiles/wp-content/ || true
  - rm -rf /var/www/html/wp-content && ln -s /mnt/afiles/wp-content /var/www/html/wp-content
  - curl -L https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip -o /tmp/sqlite.zip
  - unzip -o /tmp/sqlite.zip -d /var/www/html/wp-content/plugins
  - cp /var/www/html/wp-content/plugins/sqlite-database-integration/db.copy /var/www/html/wp-content/db.php
  - chown -R www-data:www-data /var/www/html
  - systemctl enable --now php*-fpm || systemctl enable --now php8.1-fpm || true
  - systemctl restart nginx
CLOUD
  sed -i "s/__SA__/${sa}/g" "$out"
  sed -i "s|__BLOB_SAS__|${blobsas}|g" "$out"
  sed -i "s|__FILE_SAS__|${filesas}|g" "$out"
  sed -i "s|__STOR_SUFFIX__|${STORAGE_SUFFIX}|g" "$out"
}

# ---------- 1) KREIRAJ JEDAN JEDINI PUBLIC JUMP HOST U HUBU ----------
log "Creating shared public jump host in hub..."
az vm create -g "$RG" -n "jump-host" \
  --image "$UBUNTU_IMAGE" --size "$JUMP_VM_SIZE" \
  --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
  --vnet-name "$(basename "$HUB_VNET_ID")" --subnet "instructor-subnet" \
  --public-ip-address "jump-host-pip" --nsg "" \
  --tags course="$TAG_COURSE" role="jump-host" --only-show-errors 1>/dev/null

# Pridruži NSG samo tom NIC-u (SSH s Interneta)
nicId=$(az vm show -g "$RG" -n "jump-host" --query "networkProfile.networkInterfaces[0].id" -o tsv)
nicName=$(basename "$nicId")
az network nic update -g "$RG" -n "$nicName" --network-security-group "$JUMP_HOST_NSG_ID" --only-show-errors 1>/dev/null
az vm boot-diagnostics enable -g "$RG" -n "jump-host" --only-show-errors 1>/dev/null
[[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "jump-host" --only-show-errors 1>/dev/null || true

# (Opcionalno) instruktorovi VM-ovi bez javnih IP-eva u istom subnetu (param 3.2)
if [[ "${INSTRUCTOR_VM_COUNT}" -gt 0 ]]; then
  for i in $(seq 1 "${INSTRUCTOR_VM_COUNT}"); do
    az vm create -g "$RG" -n "instr-vm${i}" \
      --image "$UBUNTU_IMAGE" --size "$VM_SIZE" \
      --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
      --vnet-name "$(basename "$HUB_VNET_ID")" --subnet "instructor-subnet" \
      --public-ip-address "" --nsg "" --tags course="$TAG_COURSE" role="instructor" --only-show-errors 1>/dev/null
    for d in 1 2; do
      az disk create -g "$RG" -n "instr-vm${i}-disk${d}" --size-gb 5 --sku "$DISK_SKU" --only-show-errors 1>/dev/null
      az vm disk attach -g "$RG" --vm-name "instr-vm${i}" --name "instr-vm${i}-disk${d}" --only-show-errors 1>/dev/null
    done
    az vm boot-diagnostics enable -g "$RG" -n "instr-vm${i}" --only-show-errors 1>/dev/null
    [[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "instr-vm${i}" --only-show-errors 1>/dev/null || true
  done
fi

# RBAC za INSTRUKTORSKU GRUPU (ako zadano) – bez Graph poziva
if [[ -n "${INSTRUCTORS_GROUP_OID:-}" ]]; then
  az role assignment create --assignee-object-id "$INSTRUCTORS_GROUP_OID" \
    --assignee-principal-type Group --role "Virtual Machine Contributor" \
    --scope "$(az group show -n "$RG" --query id -o tsv)" --only-show-errors 1>/dev/null || true
else
  log "WARN: No instructorsGroupObjectId provided; skipping instructor RBAC."
fi

# ---------- 2) STUDENTI: 1 VNET + N PRIVATNIH WP VM-ova (nema javnog IP-a) ----------
# NSG pravila na APP subnet: dozvoli SSH/HTTP samo iz HUB instructor-subnet (gdje je jump-host)
create_student_nsg(){
  local nsg="$1" src="$2"
  az network nsg create -g "$RG" -n "$nsg" --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg" -n Allow-SSH-From-Hub \
    --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$src" --destination-port-ranges 22 --only-show-errors 1>/dev/null
  az network nsg rule create -g "$RG" --nsg-name "$nsg" -n Allow-HTTP-From-Hub \
    --priority 110 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$src" --destination-port-ranges 80 --only-show-errors 1>/dev/null
}

idx=1
while IFS=',' read -r mail role; do
  [[ -z "${mail:-}" ]] && continue
  [[ "$mail" == "mail" ]] && continue  # preskoči header
  [[ "$(echo "$role" | tr '[:upper:]' '[:lower:]')" != "student" ]] && continue
  name="$(safe "${mail%@*}")"

  vnet="stu-${name}-vnet"
  appSubnet="app-subnet"
  nsgApp="stu-${name}-app-nsg"
  natPip="stu-${name}-natpip"
  natGw="stu-${name}-nat"
  sa="sa$(echo ${name} | tr -cd 'a-z0-9' | cut -c1-10)$(date +%H%M%S | tr -cd '0-9' | tail -c6)"; sa="${sa:0:23}"

  vnetCidr="$(addr_block $idx)"
  appCidr="$(app_prefix $idx)"
  idx=$((idx+1))

  log "Student $mail -> $name  VNet:$vnet ($vnetCidr) app:$appCidr"

  # VNet + APP subnet
  az network vnet create -g "$RG" -n "$vnet" --address-prefixes "$vnetCidr" \
    --subnet-name "$appSubnet" --subnet-prefixes "$appCidr" --only-show-errors 1>/dev/null

  # NSG na APP subnet (dopušta samo iz HUB-a)
  create_student_nsg "$nsgApp" "$HUB_INSTR_CIDR"
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet" --network-security-group "$nsgApp" --only-show-errors 1>/dev/null

  # NAT Gateway (izlaz na internet)
  az network public-ip create -g "$RG" -n "$natPip" --sku Standard --allocation-method Static --only-show-errors 1>/dev/null
  az network nat gateway create -g "$RG" -n "$natGw" --public-ip-addresses "$natPip" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet" --nat-gateway "$natGw" --only-show-errors 1>/dev/null

  # Storage (Blob+Files) + SAS
  az storage account create -g "$RG" -n "$sa" -l "$LOCATION" --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 --https-only true --allow-blob-public-access false --only-show-errors 1>/dev/null
  key=$(az storage account keys list -g "$RG" -n "$sa" --query "[0].value" -o tsv)
  az storage container create --account-name "$sa" --name obj --account-key "$key" --only-show-errors 1>/dev/null
  az storage share create --account-name "$sa" --name files --account-key "$key" --only-show-errors 1>/dev/null
  expiry=$(date -u -d "+365 days" +"%Y-%m-%dT%H:%MZ" 2>/dev/null || date -u -v+365d +"%Y-%m-%dT%H:%MZ")
  blobSas="$(az storage container generate-sas --account-name "$sa" --name obj --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"
  fileSas="$(az storage share generate-sas --account-name "$sa" --name files --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"

  # N WordPress VM-ova (privatni) — 3.2
  for j in $(seq 1 "${PER_USER_VM_COUNT}"); do
    vm="wp-${name}-${j}"
    ci="/tmp/${name}-cloudinit-${j}.yml"; write_cloud_init "$sa" "?${blobSas}" "?${fileSas}" "$ci"
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
    [[ "$POWER_ON" != "true" ]] && az vm deallocate -g "$RG" -n "$vm" --only-show-errors 1>/dev/null || true

    # RBAC za STUDENTSKU GRUPU (ako zadano) – kompromis 3.4
    if [[ -n "${STUDENTS_GROUP_OID:-}" ]]; then
      vmId=$(az vm show -g "$RG" -n "$vm" --query id -o tsv)
      az role assignment create --assignee-object-id "$STUDENTS_GROUP_OID" --assignee-principal-type Group \
        --role "Virtual Machine Operator" --scope "$vmId" --only-show-errors 1>/dev/null || true
      az role assignment create --assignee-object-id "$STUDENTS_GROUP_OID" --assignee-principal-type Group \
        --role "Virtual Machine Serial Console Contributor" --scope "$vmId" --only-show-errors 1>/dev/null || true
    fi
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
'''
  }
  dependsOn: [ hubVnet, uamiContributor, uamiUaa, jumpHostNsg ]
}
