# AWS SES Quota Visibility & Per-Sender Monitoring

**Account:** mohcluster (024848484634)
**Region:** eu-west-2 (London)
**Domain:** tiberbu.health
**Daily Quota:** 50,000 emails / 24h rolling window
**Incident Date:** 2026-09-16 — quota exceeded, cause unknown (no CloudTrail trail configured at the time)

---

## Background

We share one SES account across 51 IAM users (47 county HMIS + 4 app users).
All 51 share the **same 50,000/day quota** — any single sender can exhaust it for everyone.

On 2026-09-16 we exceeded the quota and could not determine which sender caused the spike
because no logging was in place. This runbook sets up per-sender visibility using:

1. **A domain-level default Configuration Set** — no app code changes required, automatically covers all current and future senders
2. **A CloudWatch Log Group** — 90 days retention, queryable with Logs Insights
3. **A tighter IAM policy** — replaces `AmazonSESFullAccess` with send-only permissions
4. **A CloudWatch Alarm** — alerts before quota is hit again

> **Why no S3 / CloudTrail trail?**
> CloudTrail Event History (free, built-in, no setup) already retains 90 days of API calls
> and is queryable via the console. CloudWatch Logs also retains SES send events for 90 days.
> An S3 trail is only needed if you require retention beyond 90 days or Athena SQL queries —
> that can be added later if compliance requires it.

---

## Lessons Learned: What Went Wrong

| Gap | Impact | Fix in this runbook |
|---|---|---|
| No logging on SES sends | Could not identify which sender caused spike | Config set → CloudWatch Logs |
| `AmazonSESFullAccess` on all users | Users can delete identities, config sets, modify account settings | Replace with `TiberbuSESSenderPolicy` |
| No quota alarm | Found out after exceeding the limit | CloudWatch Alarm at 80% |
| No per-sender attribution | All 51 users look identical in SES metrics | Domain default config set + email tags |

---

## Architecture (No App Code Changes Required)

```
tiberbu.health (SES identity)
  └── Default config set: cfgset-tiberbu-default   ← set once on the domain
        └── Event destination → CloudWatch Log Group: /aws/ses/all-senders
              └── 90-day retention
              └── Queryable via Logs Insights (per-county, per-hour, bounces)

IAM users (51 existing + any future users)
  └── TiberbuSESSenderPolicy (send-only, no admin actions)
        └── App sends email (no config set in the call)
              → IAM: ALLOW
              → SES injects domain default cfgset-tiberbu-default automatically
              → Event logged to CloudWatch ✓
              → Email delivers ✓
```

**Key point:** The domain default config set is injected by SES *after* IAM allows the call.
Apps do not need any code changes. New counties or apps added in future are automatically
covered the moment their IAM user is created and the domain default is in place.

---

## Step 1: Verify Current Quota Usage

**What this does:** Checks how many emails have been sent in the rolling 24-hour window.
The window is not midnight-to-midnight — it is a sliding 24 hours.

```bash
aws sesv2 get-account \
  --profile mohcluster \
  --region eu-west-2 \
  --query 'SendQuota'
```

**Output explained:**
```json
{
    "Max24HourSend": 50000.0,
    "MaxSendRate": 14.0,
    "SentLast24Hours": 17154.0
}
```

- `Max24HourSend` — your hard ceiling
- `SentLast24Hours` — emails sent in the last rolling 24 hours
- `MaxSendRate` — max emails per second (exceeding this throttles, does not block)

---

## Step 2: Audit IAM Users with SES Access

**What this does:** Lists all IAM users with SES permissions and confirms what policy
grants them access.

```bash
# Check policies on any specific user
aws iam list-attached-user-policies \
  --profile mohcluster \
  --user-name hmis-nairobi-SES

aws iam list-user-policies \
  --profile mohcluster \
  --user-name hmis-nairobi-SES
```

### Findings: Active SES Senders (51 users)

**Category 1: HMIS per-county (47 users)**

All currently have `AmazonSESFullAccess`. Will be replaced with `TiberbuSESSenderPolicy` in Step 6.

| IAM User | County | Notes |
|---|---|---|
| hmis-baringo-SES | Baringo | |
| hmis-bomet-SES | Bomet | |
| hmis-bungoma-SES | Bungoma | |
| hmis-busia-SES | Busia | |
| hmis-elgeyo-marakwet-SES | Elgeyo Marakwet | |
| hmis-embu-SES | Embu | |
| hmis-garissa-SES | Garissa | |
| hmis-isiolo-SES | Isiolo | |
| hmis-kajiado-SES | Kajiado | |
| hmis-kakamega-SES | Kakamega | |
| hmis-kericho-SES | Kericho | |
| hmis-kiambu-SES | Kiambu | |
| hmis-kirinyaga-SES | Kirinyaga | |
| hmis-kisii-SES | Kisii | |
| hmis-kisumu-SES | Kisumu | |
| hmis-kitui-SES | Kitui | |
| hmis-kwale-SES | Kwale | |
| hmis-laikipia-SES | Laikipia | |
| hmis-lamu-SES | Lamu | Pilot user for policy rollout |
| hmis-machakos-SES | Machakos | |
| hmis-makueni-SES | Makueni | |
| hmis-mandera-SES | Mandera | |
| hmis-marsabit-SES | Marsabit | |
| hmis-meru-SES | Meru | |
| hmis-migori-SES | Migori | |
| hmis-mombasa-SES | Mombasa | |
| hmis-muranga-SES | Murang'a | |
| hmis-nairobi-SES | Nairobi | |
| hmis-nakuru-SES | Nakuru | |
| hmis-nandi-SES | Nandi | |
| hmis-narok-SES | Narok | |
| hmis-nyamira-SES | Nyamira | |
| hmis-nyandarua-SES | Nyandarua | |
| hmis-nyeri-SES | Nyeri | |
| hmis-samburu-SES | Samburu | |
| hmis-taita-taveta-SES | Taita Taveta | |
| hmis-tana-river-SES | Tana River | |
| hmis-tharaka-nithi-SES | Tharaka Nithi | |
| hmis-transnzoia-SES | Trans Nzoia | |
| hmis-turkana-SES | Turkana | |
| hmis-uasin-gishu-SES | Uasin Gishu | |
| hmis-uat-SES | UAT environment | Has extra inline policy `DenyOutsideClusterIP` — keep it |
| hmis-vihiga-SES | Vihiga | |
| hmis-wajir-SES | Wajir | |
| hmis-west-pokot-SES | West Pokot | |

**Category 2: App/Service users (4 active SES users)**

| IAM User | App | Policy |
|---|---|---|
| client-registry-SES | Client Registry (prod) | AmazonSESFullAccess |
| client-registry-uat-SES | Client Registry (UAT) | AmazonSESFullAccess |
| compliance360-SES | Compliance360 | AmazonSESFullAccess |
| ses-smtp | Generic SMTP sender | AmazonSESFullAccess |
| simple-email-service | Generic SES sender | AmazonSESFullAccess |

> **Not SES users:** `SHRAPPPROD` and `SHRAPPUAT` only have `AmazonHealthLakeFullAccess` —
> they are not email senders and are excluded from this runbook.

---

## Step 3: Create the CloudWatch Log Group

**What this does:** Creates a single log group that will receive every SES send event
(sent, delivered, bounced, complained) from all senders. 90-day retention keeps storage
costs low while giving a full audit window.

```bash
# Create the log group
aws logs create-log-group \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/all-senders

# Set 90-day retention
aws logs put-retention-policy \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/all-senders \
  --retention-in-days 90
```

**Verify it was created:**
```bash
aws logs describe-log-groups \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name-prefix /aws/ses \
  --query 'logGroups[*].{Name:logGroupName, RetentionDays:retentionInDays}'
```

---

## Step 4: Create the Configuration Set and Wire to Log Group

**What is a Configuration Set?**
A named object in SES that routes email events to a destination (in our case, CloudWatch Logs).
When attached as a domain default, SES automatically applies it to every email sent through
`tiberbu.health` — even if the app passes nothing.

```bash
# 4a. Create the config set
aws sesv2 create-configuration-set \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-tiberbu-default
```

```bash
# 4b. Wire it to the CloudWatch log group
aws sesv2 create-configuration-set-event-destination \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-tiberbu-default \
  --event-destination-name cw-logs-dest \
  --event-destination '{
    "Enabled": true,
    "MatchingEventTypes": ["SEND","DELIVERY","BOUNCE","COMPLAINT","REJECT"],
    "CloudWatchLogsDestination": {
      "LogGroupArn": "arn:aws:logs:eu-west-2:024848484634:log-group:/aws/ses/all-senders"
    }
  }'
```

```bash
# 4c. Attach it as the domain default — ONE command that covers all 51 senders
aws sesv2 put-email-identity-configuration-set-attributes \
  --profile mohcluster \
  --region eu-west-2 \
  --email-identity tiberbu.health \
  --configuration-set-name cfgset-tiberbu-default
```

**Verify the domain default was applied:**
```bash
aws sesv2 get-email-identity \
  --profile mohcluster \
  --region eu-west-2 \
  --email-identity tiberbu.health \
  --query 'ConfigurationSetName'
```
Expected output: `"cfgset-tiberbu-default"`

---

## Step 5: Test the Pipeline End-to-End

**What this does:** Sends a real test email using your admin credentials (not any IAM user),
then verifies the event landed in CloudWatch. No IAM user is touched.

```bash
# 5a. Send a test email — replace the To address with your own
aws sesv2 send-email \
  --profile mohcluster \
  --region eu-west-2 \
  --from-email-address noreply@tiberbu.health \
  --destination '{"ToAddresses": ["elvis@tiberbu.com"]}' \
  --content '{
    "Simple": {
      "Subject": {"Data": "SES Config Set Test - ignore"},
      "Body": {"Text": {"Data": "Validating CloudWatch logging pipeline. Safe to ignore."}}
    }
  }' \
  --configuration-set-name cfgset-tiberbu-default
```

```bash
# 5b. Wait ~60 seconds, then check for a log stream
aws logs describe-log-streams \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/all-senders \
  --order-by LastEventTime \
  --descending \
  --limit 3 \
  --query 'logStreams[*].{Stream:logStreamName, LastEvent:lastEventTimestamp}'
```

```bash
# 5c. Read the actual log event — copy the stream name from the output above
aws logs get-log-events \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/all-senders \
  --log-stream-name <stream-name-from-5b> \
  --query 'events[*].message' \
  --output text | python3 -m json.tool
```

**A passing test looks like this:**
```json
{
  "eventType": "Send",
  "mail": {
    "timestamp": "2026-09-17T10:23:00Z",
    "source": "noreply@tiberbu.health",
    "destination": ["elvis@tiberbu.com"],
    "sendingAccountId": "024848484634"
  }
}
```

**What this confirms:**
- Step 5a succeeds → config set is valid
- Step 5b shows a stream → SES wrote to CloudWatch (pipeline works end-to-end)
- Step 5c shows the event → log content is readable and queryable
- You also receive the email → sending itself is not broken

---

## Step 6: Replace AmazonSESFullAccess with TiberbuSESSenderPolicy

**Why:** `AmazonSESFullAccess` gives apps the ability to delete identities, modify account
sending limits, and delete configuration sets — far more than a sending app needs.
`TiberbuSESSenderPolicy` restricts to send-only actions.

> **Note:** `ses:ConfigurationSet` is NOT a valid IAM condition key for the SES service.
> Enforcement is handled at the SES layer via the domain default, not the IAM layer.

```bash
# 6a. Save the policy document
cat > /home/elvis/ses-quota-visibility/ses-sender-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSESSendOnly",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail",
        "ses:SendBulkEmail",
        "ses:SendTemplatedEmail",
        "ses:SendBounce"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# 6b. Create it as a reusable managed policy in AWS
aws iam create-policy \
  --profile mohcluster \
  --policy-name TiberbuSESSenderPolicy \
  --policy-document file:///home/elvis/ses-quota-visibility/ses-sender-policy.json \
  --description "Send-only SES access. Admin actions (delete identity, modify limits) are excluded."
```

### Rollout: pilot one county first

Do not replace all 51 users at once. Start with Lamu (smallest county, lowest volume):

```bash
# Detach the old broad policy
aws iam detach-user-policy \
  --profile mohcluster \
  --user-name hmis-lamu-SES \
  --policy-arn arn:aws:iam::aws:policy/AmazonSESFullAccess

# Attach the new send-only policy
aws iam attach-user-policy \
  --profile mohcluster \
  --user-name hmis-lamu-SES \
  --policy-arn arn:aws:iam::024848484634:policy/TiberbuSESSenderPolicy
```

Monitor for 24 hours. If no complaints from Lamu HMIS → roll out to remaining users.

### Rollout: all remaining users (run after pilot confirmed)

```bash
# Run this only after the pilot is confirmed working
for USER in \
  hmis-baringo-SES hmis-bomet-SES hmis-bungoma-SES hmis-busia-SES \
  hmis-elgeyo-marakwet-SES hmis-embu-SES hmis-garissa-SES hmis-isiolo-SES \
  hmis-kajiado-SES hmis-kakamega-SES hmis-kericho-SES hmis-kiambu-SES \
  hmis-kirinyaga-SES hmis-kisii-SES hmis-kisumu-SES hmis-kitui-SES \
  hmis-kwale-SES hmis-laikipia-SES hmis-machakos-SES hmis-makueni-SES \
  hmis-mandera-SES hmis-marsabit-SES hmis-meru-SES hmis-migori-SES \
  hmis-mombasa-SES hmis-muranga-SES hmis-nairobi-SES hmis-nakuru-SES \
  hmis-nandi-SES hmis-narok-SES hmis-nyamira-SES hmis-nyandarua-SES \
  hmis-nyeri-SES hmis-samburu-SES hmis-taita-taveta-SES hmis-tana-river-SES \
  hmis-tharaka-nithi-SES hmis-transnzoia-SES hmis-turkana-SES hmis-uasin-gishu-SES \
  hmis-uat-SES hmis-vihiga-SES hmis-wajir-SES hmis-west-pokot-SES \
  client-registry-SES client-registry-uat-SES compliance360-SES \
  ses-smtp simple-email-service; do
    echo "Updating $USER..."
    aws iam detach-user-policy \
      --profile mohcluster \
      --user-name "$USER" \
      --policy-arn arn:aws:iam::aws:policy/AmazonSESFullAccess
    aws iam attach-user-policy \
      --profile mohcluster \
      --user-name "$USER" \
      --policy-arn arn:aws:iam::024848484634:policy/TiberbuSESSenderPolicy
done
echo "Done."
```

### Adding a new SES user in future (two commands)

```bash
aws iam create-user --profile mohcluster --user-name hmis-<county>-SES

aws iam attach-user-policy \
  --profile mohcluster \
  --user-name hmis-<county>-SES \
  --policy-arn arn:aws:iam::024848484634:policy/TiberbuSESSenderPolicy
```

The domain default config set covers them automatically — no other setup needed.

---

## Step 7: CloudWatch Logs Insights Queries

Once logs are flowing, run these in the AWS Console:
**CloudWatch → Logs → Logs Insights → select `/aws/ses/all-senders`**

**Total sends in last 24 hours:**
```
fields @timestamp, eventType
| filter eventType = "Send"
| stats count() as TotalSent
```

**Hourly send volume — find the spike:**
```
fields @timestamp, eventType
| filter eventType = "Send"
| stats count() as Sends by bin(1h)
| sort @timestamp asc
```

**Sends by source address:**
```
fields @timestamp, mail.source, eventType
| filter eventType = "Send"
| stats count() as TotalSent by mail.source
| sort TotalSent desc
```

**Bounces and complaints (deliverability health):**
```
fields @timestamp, mail.source, eventType
| filter eventType in ["Bounce", "Complaint"]
| stats count() as Issues by mail.source, eventType
| sort Issues desc
```

---

## Step 8: CloudWatch Alarm — Alert at 80% Quota

**What this does:** SES does not publish a native CloudWatch metric for `SentLast24Hours`.
The cleanest solution is a small Lambda that runs every 30 minutes, calls `sesv2 get-account`,
and publishes a custom metric — then we alarm on that metric.

**Interim option (manual check command):**
```bash
aws sesv2 get-account \
  --profile mohcluster \
  --region eu-west-2 \
  --query 'SendQuota.{Sent:SentLast24Hours, Max:Max24HourSend}'
```

**SNS topic for alerts (create now, Lambda integration added as follow-up):**
```bash
# Create the alert topic
aws sns create-topic \
  --profile mohcluster \
  --region eu-west-2 \
  --name ses-quota-alerts

# Subscribe the platform team email
aws sns subscribe \
  --profile mohcluster \
  --region eu-west-2 \
  --topic-arn arn:aws:sns:eu-west-2:024848484634:ses-quota-alerts \
  --protocol email \
  --notification-endpoint devops@tiberbu.com
```

> Lambda-based quota alarm is tracked as a follow-up item.

---

## Summary: What Each Component Does

| Component | What It Does | Covers Future Users? |
|---|---|---|
| Domain default config set | Auto-tags all sends through tiberbu.health | Yes — automatic |
| CloudWatch Log Group | 90-day store of every send/bounce/complaint event | Yes — automatic |
| Logs Insights queries | Break down sends by source, time, event type | Yes |
| TiberbuSESSenderPolicy | Restricts users to send-only actions | Yes — attach on creation |
| CloudWatch Alarm | Alerts at 80% quota before hitting ceiling | Yes |

---

## Current Status

| Step | Status | Notes |
|---|---|---|
| Quota audit | Done | 17,154 / 50,000 as of 2026-09-16 |
| IAM user audit | Done | 51 active SES senders identified |
| CloudWatch Log Group | Pending | Step 3 |
| Configuration Set + domain default | Pending | Step 4 |
| Pipeline test | Pending | Step 5 — validate before touching IAM |
| TiberbuSESSenderPolicy — pilot (Lamu) | Pending | Step 6 |
| TiberbuSESSenderPolicy — full rollout | Pending | Step 6 — after pilot confirmed |
| CloudWatch Alarm | Pending | Step 8 — Lambda follow-up |

---

## Key Contacts / Ownership

| Sender Group | Owner / Team |
|---|---|
| hmis-{county}-SES (47 users) | County HMIS teams / MOH |
| client-registry-SES | Client Registry team |
| compliance360-SES | Compliance360 team |
| ses-smtp / simple-email-service | Platform team |

---

*Document created: 2026-09-16*
*Last updated: 2026-09-17*
*Author: Platform/Security Engineering — Elvis*
