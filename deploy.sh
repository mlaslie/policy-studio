#!/usr/bin/env bash
# Deploy Policy Studio to Cloud Run behind IAP.
#   PROJECT=my-project REGION=us-east4 IAP_MEMBERS="user:me@example.com,group:team@example.com" ./deploy.sh
# Creates (idempotent): Artifact Registry repo, a read-only service account, the Cloud Run service with IAP,
# and IAP access for IAP_MEMBERS. The service runs with STUDIO_MODE=generate (no write path: discovery, audit and
# generated commands only), so the service account only gets read roles. Apply runs locally (./studio-app).
set -euo pipefail
cd "$(dirname "$0")"
GCLOUD=${GCLOUD:-gcloud}
PROJECT=${PROJECT:?set PROJECT}
REGION=${REGION:?set REGION}
SERVICE=${SERVICE:-policy-studio}
REPO=${REPO:-policy-studio}
IAP_MEMBERS=${IAP_MEMBERS:?set IAP_MEMBERS, e.g. user:me@example.com}
SA_ID=${SA_ID:-policy-studio}
SA="${SA_ID}@${PROJECT}.iam.gserviceaccount.com"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/${SERVICE}:latest"
NUM=$($GCLOUD projects describe "$PROJECT" --format='value(projectNumber)')

echo "== APIs"
$GCLOUD services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com iap.googleapis.com \
  --project "$PROJECT" --quiet

echo "== Artifact Registry repo $REPO"
$GCLOUD artifacts repositories describe "$REPO" --location "$REGION" --project "$PROJECT" >/dev/null 2>&1 || \
  $GCLOUD artifacts repositories create "$REPO" --repository-format docker --location "$REGION" --project "$PROJECT" \
    --description "Policy Studio images" --quiet

echo "== Service account $SA (read-only)"
$GCLOUD iam service-accounts describe "$SA" --project "$PROJECT" >/dev/null 2>&1 || \
  $GCLOUD iam service-accounts create "$SA_ID" --display-name "Policy Studio (read-only)" --project "$PROJECT" --quiet
# No predefined read-only role can read IAP IAM policies (only iap.admin / iap.editor, which can also write),
# so add a tiny custom role with just the getIamPolicy permissions.
ROLE_ID=${ROLE_ID:-policyStudioIapReader}
IAP_READ_PERMS="iap.web.getIamPolicy,iap.webServices.getIamPolicy,iap.webServiceVersions.getIamPolicy,iap.webTypes.getIamPolicy"
if $GCLOUD iam roles describe "$ROLE_ID" --project "$PROJECT" >/dev/null 2>&1; then
  $GCLOUD iam roles update "$ROLE_ID" --project "$PROJECT" --permissions "$IAP_READ_PERMS" --quiet >/dev/null
else
  $GCLOUD iam roles create "$ROLE_ID" --project "$PROJECT" --title "Policy Studio IAP policy reader" \
    --description "Read IAP IAM policies (Agent Registry egress grants). Read-only." \
    --permissions "$IAP_READ_PERMS" --stage GA --quiet >/dev/null
fi
# Only the read roles README.md "Permissions" lists (not roles/viewer, which reads far more than Policy Studio needs).
READ_ROLES=(roles/browser roles/serviceusage.serviceUsageViewer roles/networkservices.viewer
  roles/networksecurity.viewer roles/aiplatform.viewer roles/agentregistry.viewer roles/modelarmor.viewer
  roles/logging.viewer roles/compute.networkViewer)
for ROLE in "${READ_ROLES[@]}" "projects/${PROJECT}/roles/${ROLE_ID}" roles/serviceusage.serviceUsageConsumer; do
  $GCLOUD projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA" --role "$ROLE" \
    --condition None --quiet >/dev/null
done

echo "== Build $IMAGE"
$GCLOUD builds submit . --tag "$IMAGE" --project "$PROJECT" --region "$REGION" --quiet

echo "== Deploy Cloud Run $SERVICE with IAP"
$GCLOUD beta run deploy "$SERVICE" --image "$IMAGE" --region "$REGION" --project "$PROJECT" \
  --service-account "$SA" --no-allow-unauthenticated --iap \
  --set-env-vars "STUDIO_PROJECT=${PROJECT},STUDIO_REGION=${REGION},STUDIO_MODE=generate" \
  --min-instances 0 --max-instances 2 --memory 1Gi --timeout 300 --quiet
$GCLOUD run services add-iam-policy-binding "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --member "serviceAccount:service-${NUM}@gcp-sa-iap.iam.gserviceaccount.com" --role roles/run.invoker --quiet >/dev/null

echo "== IAP access"
IFS=',' read -ra MEMBERS <<< "$IAP_MEMBERS"
for M in "${MEMBERS[@]}"; do
  M="${M#"${M%%[![:space:]]*}"}"   # trim spaces ("user:a@example.com, group:b@example.com")
  M="${M%"${M##*[![:space:]]}"}"
  [ -n "$M" ] || continue
  $GCLOUD beta iap web add-iam-policy-binding --resource-type=cloud-run --service="$SERVICE" --region="$REGION" \
    --project="$PROJECT" --member="$M" --role=roles/iap.httpsResourceAccessor --condition=None --quiet >/dev/null
  echo "   $M"
done

URL=$($GCLOUD run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format 'value(status.url)')
echo "Policy Studio: $URL"
