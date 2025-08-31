@description('Lokacija resursa')
param location string = resourceGroup().location

@description('Veličina VM-ova (1 vCPU/1GB: Standard_B1s)')
param vmSize string = 'Standard_B1s'

@description('Veličina jump host-a')
param jumpVmSize string = 'Standard_B1s'

@description('Admin korisnik na svim VM-ovima')
param adminUsername string = 'azureuser'

@description('Admin lozinka za sve VM-ove (12–72 znakova, 3 od 4: mala/VELIKA/broj/specijalni)')
@secure()
@minLength(12)
@maxLength(72)
param adminPassword string

@description('Linux image za VM-ove (Ubuntu 22.04 LTS)')
param ubuntuImage string = 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest'

@description('Tag za sve resurse (npr. ime tečaja)')
param tagCourse string = 'cloudlearn-wp'

@minValue(2)
@description('Broj WP VM-ova po studentu (za HA; zadatak I5 traži 4)')
param perUserVmCount int = 2

@description('SKU za dodatne diskove')
param diskSku string = 'Standard_LRS'

var usersCsv = loadTextContent('users.csv') // header: mail,role

// -------------------- HUB (instruktorska mreža) --------------------
resource hubVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'hub-vnet'
  location: location
  tags: { course: tagCourse }
  properties: {
    addressSpace: { addressPrefixes: [ '10.20.0.0/16' ] }
    subnets: [
      {
        name: 'instructor-subnet'
        properties: { addressPrefix: '10.20.1.0/24' }
      }
    ]
  }
}

// (opcionalno NSG za instruktorski subnet – nema javnih IP-ova pa nije strogo nužno)
resource instructorNsg 'Microsoft.Network/networkSecurityGroups@2022-05-01' = {
  name: 'instructor-nsg'
  location: location
  tags: { course: tagCourse }
  properties: {
    securityRules: [
      // dozvoli SSH unutar vnetova (jump->instructor ili obrnutim smjerom)
      {
        name: 'Allow-SSH-Intra'
        properties: {
          access: 'Allow'
          direction: 'Inbound'
          priority: 100
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
        }
      }
    ]
  }
}

resource instructorSubnetUpdate 'Microsoft.Network/virtualNetworks/subnets@2022-05-01' = {
  name: 'instructor-subnet'
  parent: hubVnet
  properties: {
    addressPrefix: '10.20.1.0/24'
    networkSecurityGroup: { id: instructorNsg.id }
  }
}

// -------------------- Managed Identity za deployment script --------------------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'deploy-uami'
  location: location
  tags: { course: tagCourse }
}

var roleContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b24988ac-6180-42a0-ab88-20f7382dd24c') // Contributor
var roleUAA = subscriptionResourceId('Microsoft.Authorization/roleDefinitions','18d7d88d-d35e-4fb5-a5c3-7773c20a72d9') // User Access Administrator

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

// -------------------- Glavni Azure CLI deployment script --------------------
resource deployAll 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'course-deploy'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
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
      { name: 'PER_USER_VM_COUNT',         value: string(perUserVmCount) }
      { name: 'HUB_VNET_ID',               value: hubVnet.id }
      { name: 'HUB_VNET_PREFIX',           value: '10.20.0.0/16' }
      { name: 'HUB_INSTRUCTOR_SUBNET',     value: '10.20.1.0/24' }
      { name: 'RESOURCE_GROUP',            value: resourceGroup().name }
      { name: 'SUBSCRIPTION_ID',           value: subscription().subscriptionId }
    ]
    scriptContent: '''
#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ---- Login as UAMI ----
az login --identity --allow-no-subscriptions --only-show-errors 1>/dev/null
az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors

RG="$RESOURCE_GROUP"

# ---- Helpers ----

# Generate safe name (lowercase, alnum)
safe() { echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c1-20; }

# Compute per-student address prefixes (10.30.<idx>.0/24 etc.)
addr_block() {
  local idx="$1"
  echo "10.30.${idx}.0/24"
}
app_prefix() {
  local idx="$1"
  echo "10.30.${idx}.0/25"
}
jump_prefix() {
  local idx="$1"
  echo "10.30.${idx}.128/26"
}

# Create WordPress cloud-init file for a student (takes SA name + SAS tokens)
# $1: storage account name
# $2: blob container sas (leading ?)
# $3: file share sas (leading ?)
write_cloud_init() {
  local sa="$1" blobsas="$2" filesas="$3" out="$4"
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
  - cifs-utils
  - blobfuse2
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
        root /var/www/html;
        index index.php index.html index.htm;
        server_name _;
        location / {
          try_files $uri $uri/ /index.php?$args;
        }
        location ~ \.php$ {
          include snippets/fastcgi-php.conf;
          fastcgi_pass unix:/run/php/php-fpm.sock;
        }
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
          expires max;
          log_not_found off;
        }
      }
  - path: /etc/blobfuse2.yaml
    content: |
      logging:
        type: syslog
      components:
        - libfuse
      containers:
        - name: obj
          account-name: __SA__
          container: obj
          sas: "__BLOB_SAS__"
runcmd:
  - mkdir -p /mnt/objstore
  - sed -i 's/#user_allow_other/user_allow_other/' /etc/fuse.conf || true
  - blobfuse2 mount /mnt/objstore --config-file=/etc/blobfuse2.yaml --allow-other || true

  - mkdir -p /mnt/afiles
  - apt-get install -y keyutils || true
  - mount -t cifs //__SA__.file.core.windows.net/files /mnt/afiles \
      -o vers=3.0,username=AZURE\\__SA__,password=__FILE_SAS__,dir_mode=0775,file_mode=0664,serverino,nofail

  - mkdir -p /var/www/html
  - curl -L https://wordpress.org/latest.tar.gz -o /tmp/wp.tgz
  - tar -xzf /tmp/wp.tgz -C /var/www/html --strip-components=1

  - mkdir -p /mnt/afiles/wp-content
  - rsync -a /var/www/html/wp-content/ /mnt/afiles/wp-content/ || true
  - rm -rf /var/www/html/wp-content
  - ln -s /mnt/afiles/wp-content /var/www/html/wp-content

  - curl -L https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip -o /tmp/sqlite.zip
  - unzip -o /tmp/sqlite.zip -d /var/www/html/wp-content/plugins
  - cp /var/www/html/wp-content/plugins/sqlite-database-integration/db.copy /var/www/html/wp-content/db.php
  - chown -R www-data:www-data /var/www/html

  - systemctl enable --now php*-fpm || systemctl enable --now php8.1-fpm || true
  - systemctl restart nginx
CLOUD
  # inject SA + SAS
  sed -i "s/__SA__/${sa}/g" "$out"
  sed -i "s|__BLOB_SAS__|${blobsas}|g" "$out"
  sed -i "s|__FILE_SAS__|${filesas}|g" "$out"
}

# NSG rules builder for app subnet (allow jump + instructor on 22/80, ALB probes)
create_student_nsgs() {
  local nsg_app="$1" nsg_jump="$2" jump_cidr="$3" instr_cidr="$4"
  az network nsg create -g "$RG" -n "$nsg_app" --only-show-errors 1>/dev/null
  az network nsg create -g "$RG" -n "$nsg_jump" --only-show-errors 1>/dev/null

  # app NSG inbound: SSH/HTTP iz jump & instruktora
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-SSH-From-Jump \
    --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$jump_cidr" --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 22 --only-show-errors 1>/dev/null

  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-HTTP-From-Jump \
    --priority 110 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$jump_cidr" --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 80 --only-show-errors 1>/dev/null

  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-SSH-From-Instructor \
    --priority 120 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$instr_cidr" --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 22 --only-show-errors 1>/dev/null

  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-HTTP-From-Instructor \
    --priority 130 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "$instr_cidr" --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 80 --only-show-errors 1>/dev/null

  # Health probes
  az network nsg rule create -g "$RG" --nsg-name "$nsg_app" -n Allow-AzureLB-Probe \
    --priority 140 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes AzureLoadBalancer --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges '*' --only-show-errors 1>/dev/null

  # jump NSG: javni SSH
  az network nsg rule create -g "$RG" --nsg-name "$nsg_jump" -n Allow-SSH-Internet \
    --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes '*' --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 22 --only-show-errors 1>/dev/null
}

# Collect instructors without awk

INSTRUCTORS=()
while IFS=',' read -r mail role; do
  [ -z "${mail:-}" ] && continue
  rl="$(echo "$role" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
  if [[ "$rl" == "instruktor" ]]; then
    INSTRUCTORS+=("$mail")
  fi
done < <(echo "$USERS_CSV" | tail -n +2)


# -------------------- Create instructor assets --------------------
# Bastion VM + 4 instruktorska VM-a (bez javnih IP-a)
log "Creating instructor VMs in hub..."
for i in 1 2 3 4; do
  az vm create -g "$RG" -n "instr-vm${i}" \
    --image "$UBUNTU_IMAGE" --size "$VM_SIZE" \
    --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
    --vnet-name "$(basename "$HUB_VNET_ID")" --subnet "instructor-subnet" \
    --public-ip-address "" --nsg "" --tags course="$TAG_COURSE" role="instructor" \
    --only-show-errors 1>/dev/null
  # po 2 diska
  for d in 1 2; do
    az disk create -g "$RG" -n "instr-vm${i}-disk${d}" --size-gb 5 --sku "$DISK_SKU" --only-show-errors 1>/dev/null
    az vm disk attach -g "$RG" --vm-name "instr-vm${i}" --name "instr-vm${i}-disk${d}" --only-show-errors 1>/dev/null
  done
  az vm boot-diagnostics enable -g "$RG" -n "instr-vm${i}" --only-show-errors 1>/dev/null
done

# instruktor-bastion (interni)
az vm create -g "$RG" -n "instructor-bastion" \
  --image "$UBUNTU_IMAGE" --size "$JUMP_VM_SIZE" \
  --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
  --vnet-name "$(basename "$HUB_VNET_ID")" --subnet "instructor-subnet" \
  --public-ip-address "" --nsg "" --tags course="$TAG_COURSE" role="instructor-bastion" \
  --only-show-errors 1>/dev/null
az vm boot-diagnostics enable -g "$RG" -n "instructor-bastion" --only-show-errors 1>/dev/null

# RBAC za sve instruktore na RG
for mail in "${INSTRUCTORS[@]}"; do
  az role assignment create --assignee "$mail" \
    --role "Virtual Machine Contributor" \
    --scope "$(az group show -n "$RG" --query id -o tsv)" --only-show-errors 1>/dev/null || true
done

# -------------------- Per-student provisioning --------------------
idx=1

echo "$USERS_CSV" | tail -n +2 | tr -d '\r' | while IFS=',' read -r mail role; do
  [[ -z "${mail:-}" ]] && continue
  role_lc="$(echo "$role" | tr '[:upper:]' '[:lower:]')"
  [[ "$role_lc" != "student" ]] && continue

  name="$(safe "${mail%@*}")"
  vnet="stu-${name}-vnet"
  appSubnet="app-subnet"
  jumpSubnet="jump-subnet"
  nsgApp="stu-${name}-app-nsg"
  nsgJump="stu-${name}-jump-nsg"
  natPip="stu-${name}-natpip"
  natGw="stu-${name}-nat"
  lb="stu-${name}-ilb"
  fe="fe"
  be="be"
  sa="sa$(echo ${name} | tr -cd 'a-z0-9' | cut -c1-10)$(date +%H%M%S | tr -cd '0-9' | tail -c6)"
  sa="${sa:0:23}" # SA max 24 chars

  vnetCidr="$(addr_block $idx)"
  appCidr="$(app_prefix $idx)"
  jumpCidr="$(jump_prefix $idx)"

  log "Student $mail -> $name  VNet $vnet ($vnetCidr)  app:$appCidr  jump:$jumpCidr"

  # VNet + subnets
  az network vnet create -g "$RG" -n "$vnet" --address-prefixes "$vnetCidr" \
    --subnet-name "$appSubnet" --subnet-prefixes "$appCidr" --only-show-errors 1>/dev/null
  az network vnet subnet create -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --address-prefixes "$jumpCidr" --only-show-errors 1>/dev/null

  # NSG-ovi
  create_student_nsgs "$nsgApp" "$nsgJump" "$jumpCidr" "$HUB_INSTRUCTOR_SUBNET"
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet" --network-security-group "$nsgApp" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --network-security-group "$nsgJump" --only-show-errors 1>/dev/null

  # NAT Gateway za izlaz (app + jump)
  az network public-ip create -g "$RG" -n "$natPip" --sku Standard --allocation-method Static --only-show-errors 1>/dev/null
  az network nat gateway create -g "$RG" -n "$natGw" --public-ip-addresses "$natPip" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$appSubnet" --nat-gateway "$natGw" --only-show-errors 1>/dev/null
  az network vnet subnet update -g "$RG" --vnet-name "$vnet" -n "$jumpSubnet" --nat-gateway "$natGw" --only-show-errors 1>/dev/null

  # Storage (Blob + Files)
  az storage account create -g "$RG" -n "$sa" -l "$LOCATION" --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 --https-only true --allow-blob-public-access false --only-show-errors 1>/dev/null
  key=$(az storage account keys list -g "$RG" -n "$sa" --query "[0].value" -o tsv)
  az storage container create --account-name "$sa" --name obj --account-key "$key" --only-show-errors 1>/dev/null
  az storage share create --account-name "$sa" --name files --account-key "$key" --only-show-errors 1>/dev/null

  expiry=$(date -u -d "+365 days" +"%Y-%m-%dT%H:%MZ" 2>/dev/null || date -u -v+365d +"%Y-%m-%dT%H:%MZ")
  blobSas="$(az storage container generate-sas --account-name "$sa" --name obj --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"
  fileSas="$(az storage share generate-sas --account-name "$sa" --name files --permissions rlw --expiry "$expiry" --https-only --account-key "$key" -o tsv)"

  # Internal Load Balancer
  base="${appCidr%%/*}"
  IFS='.' read -r o1 o2 o3 o4 <<< "$base"
  ilb_ip="${o1}.${o2}.${o3}.10"
  az network lb create -g "$RG" -n "$lb" --sku Standard \
    --vnet-name "$vnet" --subnet "$appSubnet" \
    --frontend-ip-name "$fe" --backend-pool-name "$be" \
    --private-ip-address "$ilb_ip" \
    --only-show-errors 1>/dev/null
  az network lb probe create -g "$RG" --lb-name "$lb" -n http --protocol tcp --port 80 --only-show-errors 1>/dev/null
  az network lb rule create -g "$RG" --lb-name "$lb" -n http80 --protocol Tcp --frontend-port 80 --backend-port 80 \
    --frontend-ip-name "$fe" --backend-pool-name "$be" --probe-name http --idle-timeout 4 --only-show-errors 1>/dev/null

  # Jump host (jedini javni VM)
  az vm create -g "$RG" -n "jump-${name}" \
    --image "$UBUNTU_IMAGE" --size "$JUMP_VM_SIZE" \
    --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
    --vnet-name "$vnet" --subnet "$jumpSubnet" \
    --public-ip-address "jump-${name}-pip" --nsg "" \
    --tags course="$TAG_COURSE" owner="$mail" role="student-jump" --only-show-errors 1>/dev/null
  az vm boot-diagnostics enable -g "$RG" -n "jump-${name}" --only-show-errors 1>/dev/null

  # User-assigned identity za WP VM-ove (za buduće najmanje privilegije; trenutno koristimo SAS)
  az identity create -g "$RG" -n "uami-${name}" --only-show-errors 1>/dev/null
  uamiId=$(az identity show -g "$RG" -n "uami-${name}" --query id -o tsv)

  # cloud-init za WP (mount Blob+Files + Nginx/PHP + WP + SQLite plugin)
  ci="/tmp/${name}-cloudinit.yml"
  write_cloud_init "$sa" "?$blobSas" "?$fileSas" "$ci"

  # WP VM-ovi + diskovi + LB backend
  beId=$(az network lb address-pool show -g "$RG" --lb-name "$lb" -n "$be" --query id -o tsv)
  for j in $(seq 1 "$PER_USER_VM_COUNT"); do
    vm="wp-${name}-${j}"
    az vm create -g "$RG" -n "$vm" \
      --image "$UBUNTU_IMAGE" --size "$VM_SIZE" \
      --admin-username "$ADMIN_USERNAME" --admin-password "$ADMIN_PASSWORD" \
      --vnet-name "$vnet" --subnet "$appSubnet" \
      --public-ip-address "" --nsg "" --assign-identity "$uamiId" \
      --custom-data "$ci" \
      --tags course="$TAG_COURSE" owner="$mail" role="student-wp" --only-show-errors 1>/dev/null

    # dva dodatna diska po VM-u
    for d in 1 2; do
      az disk create -g "$RG" -n "${vm}-disk${d}" --size-gb 5 --sku "$DISK_SKU" --only-show-errors 1>/dev/null
      az vm disk attach -g "$RG" --vm-name "$vm" --name "${vm}-disk${d}" --only-show-errors 1>/dev/null
    done

    # dodaj u LB backend
    nicId=$(az vm show -g "$RG" -n "$vm" --query "networkProfile.networkInterfaces[0].id" -o tsv)
    nicName=$(basename "$nicId")
    az network nic ip-config address-pool add -g "$RG" --nic-name "$nicName" \
      --ip-config-name "ipconfig1" --address-pool "$beId" --only-show-errors 1>/dev/null

    az vm boot-diagnostics enable -g "$RG" -n "$vm" --only-show-errors 1>/dev/null
  done

  # VNet peering hub <-> student (za instruktora)
  az network vnet peering create -g "$RG" -n "hubTo-${name}" \
    --vnet-name "$(basename "$HUB_VNET_ID")" --remote-vnet "$vnet" \
    --allow-vnet-access --only-show-errors 1>/dev/null || true
  az network vnet peering create -g "$RG" -n "${name}-to-hub" \
    --vnet-name "$vnet" --remote-vnet "$(basename "$HUB_VNET_ID")" \
    --allow-vnet-access --only-show-errors 1>/dev/null || true

  # RBAC: student može upravljati samo svojim VM-ovima (start/stop/console)
  for j in $(seq 1 "$PER_USER_VM_COUNT"); do
    vmId=$(az vm show -g "$RG" -n "wp-${name}-${j}" --query id -o tsv)
    az role assignment create --assignee "$mail" --role "Virtual Machine Operator" \
      --scope "$vmId" --only-show-errors 1>/dev/null || true
    az role assignment create --assignee "$mail" --role "Virtual Machine Serial Console Contributor" \
      --scope "$vmId" --only-show-errors 1>/dev/null || true
  done
  # i na njegov jump host (da može restartati svoj jump po potrebi)
  jvmId=$(az vm show -g "$RG" -n "jump-${name}" --query id -o tsv)
  az role assignment create --assignee "$mail" --role "Virtual Machine Operator" \
    --scope "$jvmId" --only-show-errors 1>/dev/null || true

  idx=$((idx+1))
done

log "Deployment complete."
'''
  }
  dependsOn: [ uamiContributor, uamiUaa, instructorSubnetUpdate ]
}
