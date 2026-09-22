#!/usr/bin/env bash
# scan_cloud.sh - inventory of cloud-side networks.
# Every provider block is independent and skips itself cleanly when the CLI
# is absent or no credentials are available.

stage_cloud() {
  [[ "$DO_CLOUD" == 1 ]] || { info "cloud inventory disabled"; return 0; }
  section "Stage 6 - cloud network inventory"

  local any=0
  have aws     || have az || have gcloud || have kubectl || {
    info "no cloud CLI installed"
    offer_cloud_clis || { info "skipping cloud stage"; return 0; }
  }

  vault_unlock --optional >/dev/null 2>&1 || true

  cloud_aws   && any=1
  cloud_azure && any=1
  cloud_gcp   && any=1
  cloud_k8s   && any=1

  (( any )) || info "no cloud account reachable - nothing collected"
  CLOUD_FOUND=$any
}

# ---------------------------------------------------------------- AWS
cloud_aws() {
  have aws || return 1
  mkdir -p "$RAW/cloud"

  # Use existing credentials if they already work; otherwise offer the vault.
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    ask_yes_no "AWS CLI found but not authenticated. Supply AWS credentials?" n || return 1
    AWS_ACCESS_KEY_ID="$(vault_get AWS_ACCESS_KEY_ID 'AWS access key id')" || return 1
    AWS_SECRET_ACCESS_KEY="$(vault_get AWS_SECRET_ACCESS_KEY 'AWS secret access key')" || return 1
    AWS_DEFAULT_REGION="$(vault_get AWS_DEFAULT_REGION 'AWS region')" || AWS_DEFAULT_REGION="eu-central-1"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    aws sts get-caller-identity >/dev/null 2>&1 || { err "AWS credentials rejected"; return 1; }
  fi

  info "AWS authenticated"
  run_tool "AWS identity"        "$RAW/cloud/aws-identity.json"  aws sts get-caller-identity || true
  run_tool "AWS VPCs"            "$RAW/cloud/aws-vpcs.json"      aws ec2 describe-vpcs || true
  run_tool "AWS subnets"         "$RAW/cloud/aws-subnets.json"   aws ec2 describe-subnets || true
  run_tool "AWS EC2 instances"   "$RAW/cloud/aws-instances.json" aws ec2 describe-instances || true
  run_tool "AWS security groups" "$RAW/cloud/aws-sgs.json"       aws ec2 describe-security-groups || true
  run_tool "AWS load balancers"  "$RAW/cloud/aws-elb.json"       aws elbv2 describe-load-balancers || true
  run_tool "AWS Route53 zones"   "$RAW/cloud/aws-dns.json"       aws route53 list-hosted-zones || true

  # Security groups open to the whole internet are the finding people care about.
  if have jq && [[ -s "$RAW/cloud/aws-sgs.json" ]]; then
    jq -r '
      .SecurityGroups[]? as $sg
      | $sg.IpPermissions[]?
      | select(.IpRanges[]?.CidrIp == "0.0.0.0/0")
      | "\($sg.GroupId)\t\($sg.GroupName)\t\(.FromPort // "all")-\(.ToPort // "all")/\(.IpProtocol)"
    ' "$RAW/cloud/aws-sgs.json" 2>/dev/null | sort -u >"$WORK/aws-open-sgs.tsv" || true
    [[ -s "$WORK/aws-open-sgs.tsv" ]] && \
      warn "$(wc -l <"$WORK/aws-open-sgs.tsv") AWS security-group rule(s) open to 0.0.0.0/0"
  fi
  return 0
}

# ---------------------------------------------------------------- Azure
cloud_azure() {
  have az || return 1
  mkdir -p "$RAW/cloud"

  if ! az account show >/dev/null 2>&1; then
    ask_yes_no "Azure CLI found but not signed in. Sign in now?" n || return 1
    local tenant client secret
    tenant="$(vault_get AZURE_TENANT_ID 'Azure tenant id')" || return 1
    client="$(vault_get AZURE_CLIENT_ID 'Azure client (app) id')" || return 1
    secret="$(vault_get AZURE_CLIENT_SECRET 'Azure client secret')" || return 1
    # secret goes via stdin-ish env, and the whole call is silenced
    if ! az login --service-principal -u "$client" -p "$secret" --tenant "$tenant" >/dev/null 2>&1; then
      err "Azure sign-in failed"; secret=""; return 1
    fi
    secret=""
  fi

  info "Azure authenticated"
  run_tool "Azure account"        "$RAW/cloud/az-account.json" az account show || true
  run_tool "Azure virtual networks" "$RAW/cloud/az-vnets.json" az network vnet list || true
  run_tool "Azure subnets"        "$RAW/cloud/az-subnets.json" \
    bash -c 'az network vnet list --query "[].{vnet:name,rg:resourceGroup,subnets:subnets[].{name:name,prefix:addressPrefix}}" -o json' || true
  run_tool "Azure NSGs"           "$RAW/cloud/az-nsgs.json"    az network nsg list || true
  run_tool "Azure VMs"            "$RAW/cloud/az-vms.json"     az vm list -d || true
  run_tool "Azure public IPs"     "$RAW/cloud/az-pips.json"    az network public-ip list || true
  return 0
}

# ---------------------------------------------------------------- GCP
cloud_gcp() {
  have gcloud || return 1
  gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q . || {
    info "gcloud present but no active account - skipping"; return 1; }
  mkdir -p "$RAW/cloud"
  info "GCP authenticated"
  run_tool "GCP networks"   "$RAW/cloud/gcp-networks.json"  gcloud compute networks list --format=json || true
  run_tool "GCP subnets"    "$RAW/cloud/gcp-subnets.json"   gcloud compute networks subnets list --format=json || true
  run_tool "GCP instances"  "$RAW/cloud/gcp-instances.json" gcloud compute instances list --format=json || true
  run_tool "GCP firewalls"  "$RAW/cloud/gcp-firewall.json"  gcloud compute firewall-rules list --format=json || true
  return 0
}

# ---------------------------------------------------------------- Kubernetes
cloud_k8s() {
  have kubectl || return 1
  kubectl cluster-info >/dev/null 2>&1 || { info "kubectl present but no reachable cluster"; return 1; }
  mkdir -p "$RAW/cloud"
  info "Kubernetes cluster reachable"
  run_tool "k8s nodes"     "$RAW/cloud/k8s-nodes.txt"    kubectl get nodes -o wide || true
  run_tool "k8s services"  "$RAW/cloud/k8s-services.txt" kubectl get svc -A -o wide || true
  run_tool "k8s ingresses" "$RAW/cloud/k8s-ingress.txt"  kubectl get ingress -A || true
  return 0
}
