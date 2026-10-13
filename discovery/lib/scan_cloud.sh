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

  # CLOUD_PROVIDERS narrows the run, e.g. CLOUD_PROVIDERS="aws" (default: all)
  local want=" ${CLOUD_PROVIDERS:-aws azure gcp k8s} "
  [[ "$want" == *" aws "*   ]] && cloud_aws   && any=1
  [[ "$want" == *" azure "* ]] && cloud_azure && any=1
  [[ "$want" == *" gcp "*   ]] && cloud_gcp   && any=1
  [[ "$want" == *" k8s "*   ]] && cloud_k8s   && any=1

  (( any )) || info "no cloud account reachable - nothing collected"
  CLOUD_FOUND=$any
}

# ---------------------------------------------------------------- AWS
cloud_aws() {
  have aws || return 1
  mkdir -p "$RAW/cloud"

  local id; id="$(cred_first aws 2>/dev/null)"
  if [[ -n "$id" ]]; then
    # a card from the dashboard: env of the aws processes only, and none of
    # the profiles in ~/.aws mixed in
    local name; name="$(cred_name "$id")"
    export AWS_CONFIG_FILE="$SECURE_TMP/aws-config" AWS_SHARED_CREDENTIALS_FILE="$SECURE_TMP/aws-credentials"
    AWS_ACCESS_KEY_ID="$(cred_get "$id" access_key_id)"
    AWS_SECRET_ACCESS_KEY="$(cred_get "$id" secret_access_key)"
    AWS_SESSION_TOKEN="$(cred_get "$id" session_token)"
    AWS_DEFAULT_REGION="$(cred_get "$id" region)"; AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    [[ -n "$AWS_SESSION_TOKEN" ]] && export AWS_SESSION_TOKEN || unset AWS_SESSION_TOKEN
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
      err "AWS credentials rejected ($name)"; cred_result aws "$name" aws auth_failed; return 1
    fi
    cred_result aws "$name" aws ok
  # Use existing credentials if they already work; otherwise offer the vault.
  elif ! aws sts get-caller-identity >/dev/null 2>&1; then
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

  local id; id="$(cred_first azure 2>/dev/null)"
  if [[ -n "$id" ]]; then
    # a card from the dashboard: sign in to a throw-away config dir, with the
    # secret read from a 0600 file (Azure CLI @file syntax), never argv
    local name; name="$(cred_name "$id")"
    export AZURE_CONFIG_DIR="$SECURE_TMP/azure"; mkdir -p -m 700 "$AZURE_CONFIG_DIR"
    cred_file "$id" client_secret "$SECURE_TMP/az-secret"
    if ! az login --service-principal -u "$(cred_get "$id" client_id)" --password "@$SECURE_TMP/az-secret" \
          --tenant "$(cred_get "$id" tenant_id)" --allow-no-subscriptions >/dev/null 2>&1; then
      shred -u "$SECURE_TMP/az-secret" 2>/dev/null
      err "Azure sign-in failed ($name)"; cred_result azure "$name" azure auth_failed; return 1
    fi
    shred -u "$SECURE_TMP/az-secret" 2>/dev/null
    local sub; sub="$(cred_get "$id" subscription)"
    [[ -n "$sub" ]] && az account set --subscription "$sub" >/dev/null 2>&1
    cred_result azure "$name" azure ok
  elif ! az account show >/dev/null 2>&1; then
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
  local id; id="$(cred_first gcp 2>/dev/null)"
  if [[ -n "$id" ]]; then
    # a card from the dashboard: service account key in a 0600 file, gcloud
    # config in a throw-away dir
    local name; name="$(cred_name "$id")"
    export CLOUDSDK_CONFIG="$SECURE_TMP/gcloud"; mkdir -p -m 700 "$CLOUDSDK_CONFIG"
    cred_file "$id" key_json "$SECURE_TMP/gcp-key.json"
    if ! gcloud auth activate-service-account --key-file="$SECURE_TMP/gcp-key.json" >/dev/null 2>&1; then
      err "GCP sign-in failed ($name)"; cred_result gcp "$name" gcp auth_failed; return 1
    fi
    local proj; proj="$(cred_get "$id" project)"
    [[ -n "$proj" ]] || proj="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("project_id",""))' "$SECURE_TMP/gcp-key.json")"
    [[ -n "$proj" ]] && gcloud config set project "$proj" >/dev/null 2>&1
    cred_result gcp "$name" gcp ok
  fi
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
  local id name=""; id="$(cred_first k8s 2>/dev/null)"
  if [[ -n "$id" ]]; then
    name="$(cred_name "$id")"
    export KUBECONFIG="$SECURE_TMP/kubeconfig"
    cred_file "$id" kubeconfig "$KUBECONFIG"
    local ctx; ctx="$(cred_get "$id" context)"
    [[ -n "$ctx" ]] && kubectl config use-context "$ctx" >/dev/null 2>&1
  fi
  if ! kubectl cluster-info >/dev/null 2>&1; then
    [[ -n "$name" ]] && cred_result k8s "$name" k8s unreachable
    info "kubectl present but no reachable cluster"; return 1
  fi
  [[ -n "$name" ]] && cred_result k8s "$name" k8s ok
  mkdir -p "$RAW/cloud"
  info "Kubernetes cluster reachable"
  run_tool "k8s nodes"     "$RAW/cloud/k8s-nodes.txt"    kubectl get nodes -o wide || true
  run_tool "k8s services"  "$RAW/cloud/k8s-services.txt" kubectl get svc -A -o wide || true
  run_tool "k8s ingresses" "$RAW/cloud/k8s-ingress.txt"  kubectl get ingress -A || true
  return 0
}
