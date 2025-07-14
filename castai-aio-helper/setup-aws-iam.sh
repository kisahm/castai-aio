#!/bin/bash
if [ -n "${DEBUG}" ] ; then
    set -x
fi

# Get user ARN
response=$(curl -X 'POST' \
  "https://api.cast.ai/v1/kubernetes/external-clusters/${CASTAI_CLUSTER_ID}/assume-role-principal" \
  -H 'accept: application/json' \
  -H "X-API-Key: ${CASTAI_API_KEY}" \
  -d '')

if [ "$(echo "${response}" | jq -r .message)" == "Internal Server Error" ] ; then
    response=$(curl -X 'GET' \
      "https://api.cast.ai/v1/kubernetes/external-clusters/${CASTAI_CLUSTER_ID}/assume-role-principal" \
      -H 'accept: application/json' \
      -H "X-API-Key: ${CASTAI_API_KEY}")
fi

USER_ARN=$(echo "${response}" | jq -r .arn)
if [ -z ${USER_ARN} ]; then
  echo "error getting USER_ARN: ${response}"
  exit 1
fi
echo "Cast AI USER_ARN: $USER_ARN"

TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Get Region
if [ -z "${REGION}" ] ; then
    REGION=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
fi
if [ -z "${REGION}" ] ; then
    echo "Region not found"
    exit 1
fi
echo "Region: $REGION"

# Get cluster name
INSTANCE_ID=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
CLUSTER_NAME=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID |grep 'kubernetes.io/cluster'|cut -d'"' -f4|cut -d"/" -f3)
echo "EKS Cluster Name: $CLUSTER_NAME"

create_security_group() {
	SG_NAME="cast-${CLUSTER_NAME}-cluster/CastNodeSecurityGroup"
	SG_ID=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values=$CLUSTER_VPC Name=group-name,Values=$SG_NAME --region $REGION --query "SecurityGroups[*].GroupId" --output text)

	if [ -z $SG_ID ]; then
		echo "Creating new security group: '$SG_NAME'"
		SG_DESCRIPTION="CAST AI created security group that allows communication between CAST AI nodes"
		SG_TAGS="ResourceType=security-group,Tags=[{Key=Name,Value=${SG_NAME}},{Key=cast:cluster-id,Value=${CASTAI_CLUSTER_ID}}]"
		SG_ID=$(aws ec2 create-security-group --group-name $SG_NAME --description "${SG_DESCRIPTION}" --tag-specifications "${SG_TAGS}" --vpc-id $CLUSTER_VPC --region $REGION --output text --query 'GroupId')
	else
		echo "Security group already exists: '$SG_NAME'"
	fi

	# Add ingress and egress rules
	aws ec2 authorize-security-group-egress --group-id $SG_ID --region $REGION --protocol -1 --port all >>/dev/null 2>&1
	aws ec2 authorize-security-group-ingress --group-id $SG_ID --region $REGION --protocol -1 --port all --source-group $SG_ID >>/dev/null 2>&1 || true # ignore if rule already exist
}


function enable_autoscaler_agent() {
  echo "Installing autoscaler"

  echo "Installing autoscaler cloud components"
  echo "Fetching cluster information"
  CLUSTER=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --output json)
  CLUSTER_VPC=$(echo "$CLUSTER" | jq --raw-output '.cluster.resourcesVpcConfig.vpcId')

  # Get the current authentication mode
  current_auth_mode=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION | grep authenticationMode | awk '{print $2}')
  echo "Authentication mode is $current_auth_mode"

  # Validating access to a cluster only if relevant authentication mode is used.
  if [[ "$current_auth_mode" == '"CONFIG_MAP"' || $current_auth_mode == "" ]]; then
    echo "Validating cluster access"
    if ! kubectl describe cm/aws-auth --namespace=kube-system >>/dev/null 2>&1; then
      echo "Error:'aws-auth' ConfigMap is missing; it is required to be present and accessible for this authentication mode"
      exit 1
    fi
  fi

  ROLE_NAME=cast-eks-${CLUSTER_NAME:0:30}-cluster-role-${CASTAI_CLUSTER_ID:0:8}
  if [ -z $ACCOUNT_NUMBER ] ; then
    ACCOUNT_NUMBER=$(aws sts get-caller-identity --output text --query 'Account')
  fi
  ARN="${REGION}:${ACCOUNT_NUMBER}"
  ARN_PARTITION="aws"
  if [[ $REGION == us-gov-* ]]; then
  	ARN_PARTITION="aws-us-gov"
  fi

  INLINE_POLICY_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RunInstancesTagRestriction\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:instance/*\",\"Condition\":{\"StringEquals\":{\"aws:RequestTag/kubernetes.io/cluster/${CLUSTER_NAME}\":\"owned\"}}},{\"Sid\":\"RunInstancesVpcRestriction\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:subnet/*\",\"Condition\":{\"StringEquals\":{\"ec2:Vpc\":\"arn:${ARN_PARTITION}:ec2:${ARN}:vpc/${CLUSTER_VPC}\"}}},{\"Sid\":\"InstanceActionsTagRestriction\",\"Effect\":\"Allow\",\"Action\":[\"ec2:TerminateInstances\",\"ec2:StartInstances\",\"ec2:StopInstances\",\"ec2:CreateTags\"],\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:instance/*\",\"Condition\":{\"StringEquals\":{\"ec2:ResourceTag/kubernetes.io/cluster/${CLUSTER_NAME}\":[\"owned\",\"shared\"]}}},{\"Sid\":\"AutoscalingActionsTagRestriction\",\"Effect\":\"Allow\",\"Action\":[\"autoscaling:UpdateAutoScalingGroup\",\"autoscaling:SuspendProcesses\",\"autoscaling:ResumeProcesses\",\"autoscaling:TerminateInstanceInAutoScalingGroup\"],\"Resource\":\"arn:${ARN_PARTITION}:autoscaling:${ARN}:autoScalingGroup:*:autoScalingGroupName/*\",\"Condition\":{\"StringEquals\":{\"autoscaling:ResourceTag/kubernetes.io/cluster/${CLUSTER_NAME}\":[\"owned\",\"shared\"]}}},{\"Sid\":\"EKS\",\"Effect\":\"Allow\",\"Action\":[\"eks:Describe*\",\"eks:List*\",\"eks:TagResource\",\"eks:UntagResource\"],\"Resource\":[\"arn:${ARN_PARTITION}:eks:${ARN}:cluster/${CLUSTER_NAME}\",\"arn:${ARN_PARTITION}:eks:${ARN}:nodegroup/${CLUSTER_NAME}/*/*\"]}]}"
  POLICY_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PassRoleEC2\",\"Action\":\"iam:PassRole\",\"Effect\":\"Allow\",\"Resource\":\"arn:${ARN_PARTITION}:iam::*:role/*\",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"ec2.amazonaws.com\"}}},{\"Sid\":\"NonResourcePermissions\",\"Effect\":\"Allow\",\"Action\":[\"iam:CreateServiceLinkedRole\",\"ec2:CreateKeyPair\",\"ec2:DeleteKeyPair\",\"ec2:CreateTags\",\"ec2:ImportKeyPair\"],\"Resource\":\"*\"},{\"Sid\":\"RunInstancesPermissions\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":[\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:network-interface/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:security-group/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:volume/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:key-pair/*\",\"arn:${ARN_PARTITION}:ec2:*::image/*\"]}]}"
  ASSUME_ROLE_POLICY_JSON='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'"$USER_ARN"'"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"'"$CASTAI_CLUSTER_ID"'"}}}]}'

  if aws iam get-role --role-name $ROLE_NAME >>/dev/null 2>&1; then
  	echo "Role already exists: '$ROLE_NAME'"
  	ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --output text --query 'Role.Arn')
  	ROLE_CURRENT_POLICY=$(aws iam get-role --role-name $ROLE_NAME  --output json --query 'Role.AssumeRolePolicyDocument')
      if ! json_equal "$ROLE_CURRENT_POLICY" "$ASSUME_ROLE_POLICY_JSON"; then
          echo "Updating $ROLE_NAME role policy"
          aws iam update-assume-role-policy --role-name $ROLE_NAME --policy-document $ASSUME_ROLE_POLICY_JSON
      else
          echo "$ROLE_NAME role policy is up to date"
      fi
  else
  	echo "Creating new role: '$ROLE_NAME'"
  	ROLE_ARN=$(aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document $ASSUME_ROLE_POLICY_JSON --description "Role to manage '$CLUSTER_NAME' EKS cluster used by CAST AI" --output text --query 'Role.Arn')
  fi

  INSTANCE_PROFILE="cast-${CLUSTER_NAME:0:40}-eks-${CASTAI_CLUSTER_ID:0:8}"
  if aws iam get-instance-profile --instance-profile-name $INSTANCE_PROFILE >>/dev/null 2>&1; then
  	echo "Instance profile already exists: '$INSTANCE_PROFILE'"
  	INSTANCE_ROLE_ARN=$(aws iam get-role --role-name $INSTANCE_PROFILE --output text --query 'Role.Arn')
  	aws iam add-role-to-instance-profile --instance-profile-name $INSTANCE_PROFILE --role-name $INSTANCE_PROFILE >>/dev/null 2>&1 || true
  else
  	ASSUME_ROLE_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ec2.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}"

  	if aws iam get-role --role-name $INSTANCE_PROFILE >>/dev/null 2>&1; then
  		echo "Instance role already exists: '$INSTANCE_PROFILE'"
  		INSTANCE_ROLE_ARN=$(aws iam get-role --role-name $INSTANCE_PROFILE --output text --query 'Role.Arn')
  	else
  		echo "Creating new instance role: '$INSTANCE_PROFILE'"
  		INSTANCE_ROLE_ARN=$(aws iam create-role --role-name $INSTANCE_PROFILE --description 'EKS node instance role used by CAST AI' --assume-role-policy-document $ASSUME_ROLE_JSON --output text --query 'Role.Arn')
  	fi
  	# Create policy for IPv6
    IPv6_POLICY_NAME="CastEC2AssignIPv6Policy"
    IPv6_POLICY_DOCUMENT="{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"ec2:AssignIpv6Addresses\",\"Resource\": \"*\"}]}"
    EXISTING_CAST_AI_IPv6_POLICY_ARN=$(aws iam list-policies --no-cli-pager   --query "Policies[?PolicyName=='$IPv6_POLICY_NAME'].Arn" --output text)
    # Check if the policy created by EKS module exists.
    EXISTING_IPv6_POLICY_ARN=$(aws iam list-policies --no-cli-pager   --query "Policies[?PolicyName=='AmazonEKS_CNI_IPv6_Policy'].Arn" --output text)
    if [ -z "$EXISTING_IPv6_POLICY_ARN" ]; then
      # Create the policy
      if [ -z "$EXISTING_CAST_AI_IPv6_POLICY_ARN" ]; then
        echo "Policy AmazonEKS_CNI_IPv6_Policy doesn't exist creating custom CAST AI IPv6"
        echo "Creating policy $IPv6_POLICY_NAME..."
        POLICY_ARN=$(aws iam create-policy --policy-name "$IPv6_POLICY_NAME" --policy-document "$IPv6_POLICY_DOCUMENT" --query "Policy.Arn" --output text)
        IPv6_ROLE_TO_ADD=$POLICY_ARN
      else
        IPv6_ROLE_TO_ADD=$EXISTING_CAST_AI_IPv6_POLICY_ARN
        echo "Policy $EXISTING_CAST_AI_IPv6_POLICY_ARN already exists with ARN: $EXISTING_CAST_AI_IPv6_POLICY_ARN"
      fi
    else
     echo "Policy AmazonEKS_CNI_IPv6_Policy already exists with ARN: $EXISTING_IPv6_POLICY_ARN"
     IPv6_ROLE_TO_ADD=$EXISTING_IPv6_POLICY_ARN
    fi

  	role_policies=(arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy $IPv6_ROLE_TO_ADD)
  	echo "Attaching policies to the instance role: '$INSTANCE_PROFILE'"
  	for i in "${role_policies[@]}"; do
  	  echo "Attaching policy $i"
  		aws iam attach-role-policy --role-name $INSTANCE_PROFILE --policy-arn $i
  	done
  	echo "Creating new instance profile: '$INSTANCE_PROFILE'"
  	aws iam create-instance-profile --instance-profile-name $INSTANCE_PROFILE >>/dev/null 2>&1
  	echo "Adding role to new instance profile: '$INSTANCE_PROFILE'"
  	aws iam add-role-to-instance-profile --instance-profile-name $INSTANCE_PROFILE --role-name $INSTANCE_PROFILE
  fi

  create_security_group

  echo "Attaching policies to the role"
  POLICY_ARN="arn:aws:iam::${ACCOUNT_NUMBER}:policy/CastEKSPolicy"
  if aws iam get-policy --policy-arn $POLICY_ARN >>/dev/null 2>&1; then

      LAST_VERSION_ID=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'Versions[0].VersionId')
      CURRENT_POLICY_CONTENT=$(aws iam get-policy-version --policy-arn $POLICY_ARN --version-id $LAST_VERSION_ID --query "PolicyVersion.Document" --output json)
      if ! json_equal "$CURRENT_POLICY_CONTENT" "$POLICY_JSON"; then
          echo "$POLICY_ARN policy already exist with outdated version"
          VERSIONS=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'length(Versions[*])')
          if [ "$VERSIONS" -gt "4" ]; then
              OLDEST_VERSION_ID=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'Versions[-1].VersionId')
              echo "Deleting old $POLICY_ARN policy version $OLDEST_VERSION_ID"
              aws iam delete-policy-version --policy-arn $POLICY_ARN --version-id $OLDEST_VERSION_ID
          fi
          echo "Creating new $POLICY_ARN policy version"
          aws iam create-policy-version --policy-arn $POLICY_ARN --policy-document $POLICY_JSON --set-as-default >>/dev/null 2>&1
      else
          echo "$POLICY_ARN policy already exist with newest version"
      fi
  else
  	POLICY_ARN=$(aws iam create-policy --policy-name CastEKSPolicy --policy-document $POLICY_JSON --description "Policy to manage EKS cluster used by CAST AI" --output text --query 'Policy.Arn')
  fi

  policies=(arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess arn:aws:iam::aws:policy/IAMReadOnlyAccess $POLICY_ARN)
  for i in "${policies[@]}"; do
  	aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn $i
  done

  aws iam put-role-policy --role-name $ROLE_NAME --policy-name CastEKSRestrictedAccess --policy-document $INLINE_POLICY_JSON

  # Check if the current authentication mode matches the desired one
  if [[ $current_auth_mode == *API* ]]; then
      echo "Check count of access entries for $INSTANCE_ROLE_ARN"
      COUNT=$(aws eks list-access-entries --cluster-name $CLUSTER_NAME --region $REGION | grep  $INSTANCE_ROLE_ARN| wc -l)
      if [[ $COUNT -eq 0 ]]; then
        echo "Adding access entries"
        aws eks create-access-entry --cluster-name $CLUSTER_NAME --principal-arn $INSTANCE_ROLE_ARN --type EC2_LINUX --region $REGION
      fi
  fi

  if [[ "$current_auth_mode" == '"CONFIG_MAP"' || $current_auth_mode == "" ]]; then
    echo "Adding node role to cm/aws-auth: '$INSTANCE_ROLE_ARN'"
    CAST_NODE_ROLE_JSON="{\"groups\": [\"system:bootstrappers\", \"system:nodes\"], \"rolearn\": \"${INSTANCE_ROLE_ARN}\", \"username\": \"system:node:{{EC2PrivateDNSName}}\"}"
    MAP_ROLES=$(kubectl get -n kube-system cm/aws-auth -o json | jq -r '.data.mapRoles // ""')
    OUTPUT_FORMAT="yaml"
    YAML_STYLE="default"

    if [ -z "$MAP_ROLES" ]; then
      echo "mapRoles is empty. Initializing a new list."
      CURRENT_ROLES="[]"
    else
      # JSON is a valid YAML, so we can use yq to parse the mapRoles even if it is in JSON format.
      CURRENT_ROLES=$(echo "$MAP_ROLES" | yq -o json e -)
      # Decide on output format.
      if echo "$MAP_ROLES" | jq empty 2>/dev/null; then
        echo "Detected aws-auth roles format: JSON"
        OUTPUT_FORMAT="json"
        # Ensure that jq behaves consistently with yq. They must always be consistent unless jq and/or yq installations are broken.
        if ! json_equal "$(echo "$MAP_ROLES" | jq -c .)" $CURRENT_ROLES; then
          echo "jq and yq produce inconsistent output. Please check your jq and yq installations." 
          exit 1
        fi
      else
        echo "Detected aws-auth roles format: YAML"
        OUTPUT_FORMAT="yaml"
        if echo "$MAP_ROLES" | grep -q '"rolearn":' ; then
          echo "Will use double quote style"
          YAML_STYLE="double"
        fi
      fi
    fi

    if echo "$CURRENT_ROLES" | jq -e ".[] | select(.rolearn == \"${INSTANCE_ROLE_ARN}\")" >/dev/null; then
      echo "Node role already exists in cm/aws-auth"
    else
      UPDATED_ROLES_JSON=$(echo "$CURRENT_ROLES" | jq -c ". + [${CAST_NODE_ROLE_JSON}]")

      if [ "$OUTPUT_FORMAT" = "yaml" ]; then
        if [ "$YAML_STYLE" = "double" ]; then
          UPDATED_ROLES=$(echo "$UPDATED_ROLES_JSON" | yq eval -P | yq '... style="double"' -)
        else
          UPDATED_ROLES=$(echo "$UPDATED_ROLES_JSON" | yq eval -P -)
        fi
      else
        UPDATED_ROLES="$UPDATED_ROLES_JSON"
      fi
      PATCH_JSON="{\"data\":{\"mapRoles\": $(echo "$UPDATED_ROLES" | jq -sR .)}}"

      echo "Performing client/server checks for kubectl configmap patch..."
      set +e
      DRY_RUN_OUTPUT=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=client 2>&1)
      if [[ $? -ne 0 ]]; then
        echo "Client dry-run failed:"
        echo "$DRY_RUN_OUTPUT"
        echo "Aborting patch. Please, update aws-auth configmap manually with: "
        if [ "$OUTPUT_FORMAT" = "yaml" ]; then
          echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
        else
          echo "$CAST_NODE_ROLE_JSON" | jq .
        fi
      else
        echo "Client dry-run passed, going to perform dry-run on server side..."
        DRY_RUN_OUTPUT=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=server 2>&1)
        if [ $? -eq 0 ]; then
          DATA_BEFORE=$(kubectl get -n kube-system cm/aws-auth -o=jsonpath='{.data}')
          DATA_AFTER=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=server -o=jsonpath='{.data}')
          # Ensure we are not deleting but adding.
          if [ "${#DATA_BEFORE}" -gt "${#DATA_AFTER}" ]; then
            echo "Server dry-run failed: patch would delete data"
            echo "Aborting patch. Please, update aws-auth configmap manually with: "
            if [ "$OUTPUT_FORMAT" = "yaml" ]; then
              echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
            else
              echo "$CAST_NODE_ROLE_JSON" | jq .
            fi
          else
            echo "Server dry-run successful. Applying the patch..."
            kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON"
            echo "Node role added successfully to cm/aws-auth"
          fi
        else
          echo "Server dry-run failed:"
          echo "$DRY_RUN_OUTPUT"
          echo "Aborting patch. Please, update aws-auth configmap manually with: "
          if [ "$OUTPUT_FORMAT" = "yaml" ]; then
            echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
          else
            echo "$CAST_NODE_ROLE_JSON" | jq .
          fi
        fi
      fi
      set -e
    fi
  fi


  echo "Role ARN: ${ROLE_ARN}"
  API_URL="${CASTAI_API_URL}/v1/kubernetes/external-clusters/${CASTAI_CLUSTER_ID}"
  BODY='{"eks": { "assumeRoleArn": "'"$ROLE_ARN"'" }}'

  echo "Sending role ARN to CAST AI console..."
  RESPONSE=$(curl -sSL --write-out "HTTP_STATUS:%{http_code}" -X POST -H "X-API-Key: ${CASTAI_API_KEY}" -d "${BODY}" $API_URL)
  RESPONSE_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
  RESPONSE_BODY=$(echo "$RESPONSE" | sed -e 's/HTTP_STATUS\:.*//g')

  if [[ $RESPONSE_STATUS -eq 200 ]]; then
    echo "Successfully sent."
  else
    echo "Couldn't save role ARN to CAST AI console. Try updating cluster role ARN manually."
    echo "Error details: status=$RESPONSE_STATUS content=$RESPONSE_BODY"
    exit 1
  fi
}

enable_autoscaler_agent