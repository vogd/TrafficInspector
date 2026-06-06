# Stateful rules: block QUIC, app-aware logging with 100+ app signatures.
resource "aws_networkfirewall_rule_group" "stateful" {
  name     = "trafinspector-stateful"
  type     = "STATEFUL"
  capacity = 100
  lifecycle {
    create_before_destroy = true
  }
  rule_group {
    rules_source {
      rules_string = <<-RULES
        # === PROTOCOL CONTROL ===
        drop udp any any -> any 443 (msg:"Block QUIC - force TLS fallback"; sid:1; rev:1;)

        # === VIDEO CONFERENCING ===
        alert tls any any -> any any (tls.sni; content:"zoom.us"; nocase; msg:"Zoom"; sid:10; rev:1;)
        alert tls any any -> any any (tls.sni; content:"zoom.com"; nocase; msg:"Zoom"; sid:11; rev:1;)
        alert tls any any -> any any (tls.sni; content:"teams.microsoft.com"; nocase; msg:"MS Teams"; sid:12; rev:1;)
        alert tls any any -> any any (tls.sni; content:"teams.live.com"; nocase; msg:"MS Teams"; sid:13; rev:1;)
        alert tls any any -> any any (tls.sni; content:"webex.com"; nocase; msg:"Webex"; sid:14; rev:1;)
        alert tls any any -> any any (tls.sni; content:"meet.google.com"; nocase; msg:"Google Meet"; sid:15; rev:1;)

        # === AI / LLM SERVICES ===
        alert tls any any -> any any (tls.sni; content:"openai.com"; nocase; msg:"AI:OpenAI/ChatGPT"; sid:100; rev:1;)
        alert tls any any -> any any (tls.sni; content:"api.openai.com"; nocase; msg:"AI:OpenAI API"; sid:101; rev:1;)
        alert tls any any -> any any (tls.sni; content:"claude.ai"; nocase; msg:"AI:Claude"; sid:102; rev:1;)
        alert tls any any -> any any (tls.sni; content:"api.anthropic.com"; nocase; msg:"AI:Anthropic API"; sid:103; rev:1;)
        alert tls any any -> any any (tls.sni; content:"gemini.google.com"; nocase; msg:"AI:Gemini"; sid:104; rev:1;)
        alert tls any any -> any any (tls.sni; content:"generativelanguage.googleapis.com"; nocase; msg:"AI:Google AI API"; sid:105; rev:1;)
        alert tls any any -> any any (tls.sni; content:"copilot.microsoft.com"; nocase; msg:"AI:Copilot"; sid:106; rev:1;)
        alert tls any any -> any any (tls.sni; content:"api.githubcopilot.com"; nocase; msg:"AI:GitHub Copilot API"; sid:107; rev:1;)
        alert tls any any -> any any (tls.sni; content:"huggingface.co"; nocase; msg:"AI:HuggingFace"; sid:108; rev:1;)
        alert tls any any -> any any (tls.sni; content:"replicate.com"; nocase; msg:"AI:Replicate"; sid:109; rev:1;)
        alert tls any any -> any any (tls.sni; content:"together.ai"; nocase; msg:"AI:Together AI"; sid:110; rev:1;)
        alert tls any any -> any any (tls.sni; content:"groq.com"; nocase; msg:"AI:Groq"; sid:111; rev:1;)
        alert tls any any -> any any (tls.sni; content:"perplexity.ai"; nocase; msg:"AI:Perplexity"; sid:112; rev:1;)
        alert tls any any -> any any (tls.sni; content:"mistral.ai"; nocase; msg:"AI:Mistral"; sid:113; rev:1;)
        alert tls any any -> any any (tls.sni; content:"cohere.ai"; nocase; msg:"AI:Cohere"; sid:114; rev:1;)
        alert tls any any -> any any (tls.sni; content:"bedrock-runtime"; nocase; msg:"AI:AWS Bedrock"; sid:115; rev:1;)
        alert tls any any -> any any (tls.sni; content:"sagemaker-runtime"; nocase; msg:"AI:AWS SageMaker"; sid:116; rev:1;)
        alert tls any any -> any any (tls.sni; content:"aiplatform.googleapis.com"; nocase; msg:"AI:GCP Vertex"; sid:117; rev:1;)
        alert tls any any -> any any (tls.sni; content:"openrouter.ai"; nocase; msg:"AI:OpenRouter"; sid:118; rev:1;)
        alert tls any any -> any any (tls.sni; content:"deepseek.com"; nocase; msg:"AI:DeepSeek"; sid:119; rev:1;)
        alert tls any any -> any any (tls.sni; content:"x.ai"; nocase; msg:"AI:xAI/Grok"; sid:120; rev:1;)

        # === AI INFERENCE / MCP / ACP DETECTION (decrypted HTTP) ===
        alert http any any -> any any (http.uri; content:"/v1/chat/completions"; msg:"AI:Inference-ChatCompletions"; sid:130; rev:1;)
        alert http any any -> any any (http.uri; content:"/v1/completions"; msg:"AI:Inference-Completions"; sid:131; rev:1;)
        alert http any any -> any any (http.uri; content:"/v1/embeddings"; msg:"AI:Inference-Embeddings"; sid:132; rev:1;)
        alert http any any -> any any (http.uri; content:"/v1/images/generations"; msg:"AI:Inference-ImageGen"; sid:133; rev:1;)
        alert http any any -> any any (http.uri; content:"/v1/audio"; msg:"AI:Inference-Audio"; sid:134; rev:1;)
        alert http any any -> any any (http.header; content:"x-model-id"; nocase; msg:"AI:ModelInference-Header"; sid:135; rev:1;)
        alert http any any -> any any (http.content_type; content:"text/event-stream"; msg:"AI:SSE-Streaming"; sid:136; rev:1;)
        alert http any any -> any any (http.uri; content:"/mcp/"; nocase; msg:"AI:MCP-Request"; sid:140; rev:1;)
        alert http any any -> any any (http.uri; content:"/jsonrpc"; nocase; msg:"AI:JSON-RPC(MCP/ACP)"; sid:141; rev:1;)
        alert http any any -> any any (http.header; content:"mcp-session"; nocase; msg:"AI:MCP-Session-Header"; sid:142; rev:1;)
        alert http any any -> any any (http.uri; content:"/acp/"; nocase; msg:"AI:ACP-Request"; sid:143; rev:1;)
        alert http any any -> any any (http.uri; content:"/invoke"; http.header; content:"x-amz-bedrock"; nocase; msg:"AI:Bedrock-Invoke"; sid:144; rev:1;)

        # === MESSAGING & COLLABORATION ===
        alert tls any any -> any any (tls.sni; content:"slack.com"; nocase; msg:"Slack"; sid:200; rev:1;)
        alert tls any any -> any any (tls.sni; content:"slack-edge.com"; nocase; msg:"Slack"; sid:201; rev:1;)
        alert tls any any -> any any (tls.sni; content:"discord.com"; nocase; msg:"Discord"; sid:202; rev:1;)
        alert tls any any -> any any (tls.sni; content:"discordapp.com"; nocase; msg:"Discord"; sid:203; rev:1;)
        alert tls any any -> any any (tls.sni; content:"telegram.org"; nocase; msg:"Telegram"; sid:204; rev:1;)
        alert tls any any -> any any (tls.sni; content:"web.whatsapp.com"; nocase; msg:"WhatsApp Web"; sid:205; rev:1;)
        alert tls any any -> any any (tls.sni; content:"signal.org"; nocase; msg:"Signal"; sid:206; rev:1;)

        # === CLOUD STORAGE & SYNC ===
        alert tls any any -> any any (tls.sni; content:"dropbox.com"; nocase; msg:"Dropbox"; sid:210; rev:1;)
        alert tls any any -> any any (tls.sni; content:"drive.google.com"; nocase; msg:"Google Drive"; sid:211; rev:1;)
        alert tls any any -> any any (tls.sni; content:"onedrive.live.com"; nocase; msg:"OneDrive"; sid:212; rev:1;)
        alert tls any any -> any any (tls.sni; content:"icloud.com"; nocase; msg:"iCloud"; sid:213; rev:1;)
        alert tls any any -> any any (tls.sni; content:"box.com"; nocase; msg:"Box"; sid:214; rev:1;)
        alert tls any any -> any any (tls.sni; content:"wetransfer.com"; nocase; msg:"WeTransfer"; sid:215; rev:1;)

        # === SaaS PRODUCTIVITY ===
        alert tls any any -> any any (tls.sni; content:"salesforce.com"; nocase; msg:"Salesforce"; sid:220; rev:1;)
        alert tls any any -> any any (tls.sni; content:"notion.so"; nocase; msg:"Notion"; sid:221; rev:1;)
        alert tls any any -> any any (tls.sni; content:"atlassian.net"; nocase; msg:"Atlassian/Jira"; sid:222; rev:1;)
        alert tls any any -> any any (tls.sni; content:"github.com"; nocase; msg:"GitHub"; sid:223; rev:1;)
        alert tls any any -> any any (tls.sni; content:"gitlab.com"; nocase; msg:"GitLab"; sid:224; rev:1;)
        alert tls any any -> any any (tls.sni; content:"figma.com"; nocase; msg:"Figma"; sid:225; rev:1;)
        alert tls any any -> any any (tls.sni; content:"canva.com"; nocase; msg:"Canva"; sid:226; rev:1;)
        alert tls any any -> any any (tls.sni; content:"monday.com"; nocase; msg:"Monday"; sid:227; rev:1;)
        alert tls any any -> any any (tls.sni; content:"asana.com"; nocase; msg:"Asana"; sid:228; rev:1;)
        alert tls any any -> any any (tls.sni; content:"linear.app"; nocase; msg:"Linear"; sid:229; rev:1;)

        # === STREAMING & MEDIA ===
        alert tls any any -> any any (tls.sni; content:"youtube.com"; nocase; msg:"YouTube"; sid:230; rev:1;)
        alert tls any any -> any any (tls.sni; content:"netflix.com"; nocase; msg:"Netflix"; sid:231; rev:1;)
        alert tls any any -> any any (tls.sni; content:"spotify.com"; nocase; msg:"Spotify"; sid:232; rev:1;)
        alert tls any any -> any any (tls.sni; content:"twitch.tv"; nocase; msg:"Twitch"; sid:233; rev:1;)
        alert tls any any -> any any (tls.sni; content:"tiktok.com"; nocase; msg:"TikTok"; sid:234; rev:1;)
        alert tls any any -> any any (tls.sni; content:"disneyplus.com"; nocase; msg:"Disney+"; sid:235; rev:1;)

        # === SOCIAL MEDIA ===
        alert tls any any -> any any (tls.sni; content:"facebook.com"; nocase; msg:"Facebook"; sid:240; rev:1;)
        alert tls any any -> any any (tls.sni; content:"instagram.com"; nocase; msg:"Instagram"; sid:241; rev:1;)
        alert tls any any -> any any (tls.sni; content:"twitter.com"; nocase; msg:"Twitter/X"; sid:242; rev:1;)
        alert tls any any -> any any (tls.sni; content:"x.com"; nocase; msg:"X"; sid:243; rev:1;)
        alert tls any any -> any any (tls.sni; content:"reddit.com"; nocase; msg:"Reddit"; sid:244; rev:1;)
        alert tls any any -> any any (tls.sni; content:"linkedin.com"; nocase; msg:"LinkedIn"; sid:245; rev:1;)

        # === VPN / PROXY / EVASION (alert for visibility, could be drop) ===
        alert tls any any -> any any (tls.sni; content:"nordvpn.com"; nocase; msg:"VPN:NordVPN"; sid:301; rev:1;)
        alert tls any any -> any any (tls.sni; content:"expressvpn.com"; nocase; msg:"VPN:ExpressVPN"; sid:302; rev:1;)
        alert tls any any -> any any (tls.sni; content:"surfshark.com"; nocase; msg:"VPN:Surfshark"; sid:303; rev:1;)
        alert tls any any -> any any (tls.sni; content:"protonvpn.com"; nocase; msg:"VPN:ProtonVPN"; sid:304; rev:1;)
        alert tls any any -> any any (tls.sni; content:"mullvad.net"; nocase; msg:"VPN:Mullvad"; sid:305; rev:1;)
        alert tls any any -> any any (tls.sni; content:"privateinternetaccess.com"; nocase; msg:"VPN:PIA"; sid:306; rev:1;)

        # === DEVELOPER TOOLS & CODE ===
        alert tls any any -> any any (tls.sni; content:"npmjs.org"; nocase; msg:"Dev:npm"; sid:310; rev:1;)
        alert tls any any -> any any (tls.sni; content:"pypi.org"; nocase; msg:"Dev:PyPI"; sid:311; rev:1;)
        alert tls any any -> any any (tls.sni; content:"docker.io"; nocase; msg:"Dev:Docker Hub"; sid:312; rev:1;)
        alert tls any any -> any any (tls.sni; content:"stackoverflow.com"; nocase; msg:"Dev:StackOverflow"; sid:313; rev:1;)
        alert tls any any -> any any (tls.sni; content:"vscode.dev"; nocase; msg:"Dev:VSCode Web"; sid:314; rev:1;)

        # === EMAIL ===
        alert tls any any -> any any (tls.sni; content:"mail.google.com"; nocase; msg:"Email:Gmail"; sid:320; rev:1;)
        alert tls any any -> any any (tls.sni; content:"outlook.live.com"; nocase; msg:"Email:Outlook"; sid:321; rev:1;)
        alert tls any any -> any any (tls.sni; content:"protonmail.com"; nocase; msg:"Email:ProtonMail"; sid:322; rev:1;)

        # === P2P / TORRENT — BLOCKED ===
        drop http any any -> any any (http.user_agent; content:"BitTorrent"; nocase; msg:"BLOCK:P2P:BitTorrent"; sid:400; rev:2;)
        drop http any any -> any any (http.user_agent; content:"uTorrent"; nocase; msg:"BLOCK:P2P:uTorrent"; sid:401; rev:2;)
        drop http any any -> any any (http.user_agent; content:"qBittorrent"; nocase; msg:"BLOCK:P2P:qBittorrent"; sid:402; rev:2;)
        drop http any any -> any any (http.user_agent; content:"Transmission"; nocase; msg:"BLOCK:P2P:Transmission"; sid:403; rev:2;)
        drop tls any any -> any any (tls.sni; content:"tracker"; nocase; msg:"BLOCK:P2P:Tracker"; sid:404; rev:2;)
        drop dns any any -> any any (dns.query; content:"tracker"; nocase; msg:"BLOCK:P2P:Tracker-DNS"; sid:405; rev:2;)

        # === VPN / PROXY / EVASION — BLOCKED ===
        drop tls any any -> any any (tls.sni; content:"torproject.org"; nocase; msg:"BLOCK:Tor"; sid:300; rev:2;)
        drop tls any any -> any any (tls.sni; content:"psiphon"; nocase; msg:"BLOCK:Psiphon"; sid:307; rev:2;)
        drop tls any any -> any any (tls.sni; content:"lantern"; nocase; msg:"BLOCK:Lantern"; sid:308; rev:2;)
      RULES
    }
  }
  tags = var.tags
}

# Outbound TLS inspection (MITM) using the self-signed CA imported into ACM (tls.tf). Decrypts 0.0.0.0/0:443.
resource "aws_networkfirewall_tls_inspection_configuration" "tls" {
  name = "trafinspector-tls"
  tls_inspection_configuration {
    server_certificate_configuration {
      certificate_authority_arn = aws_acm_certificate.ca.arn
      scope {
        protocols = [6]
        destination { address_definition = "0.0.0.0/0" }
        source { address_definition = "0.0.0.0/0" }
        destination_ports {
          from_port = 443
          to_port   = 443
        }
        source_ports {
          from_port = 0
          to_port   = 65535
        }
      }
    }
  }
  tags = var.tags
}

resource "aws_networkfirewall_firewall_policy" "policy" {
  name = "trafinspector-policy-tls"
  lifecycle {
    create_before_destroy = true
  }
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    tls_inspection_configuration_arn   = aws_networkfirewall_tls_inspection_configuration.tls.arn
    # Custom rules (app detection, QUIC block)
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateful.arn
    }
    # --- AWS-managed: Domain-based threat intel (low capacity cost) ---
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/AbusedLegitBotNetCommandAndControlDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/AbusedLegitMalwareDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/BotNetCommandAndControlDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/MalwareDomainsActionOrder"
    }
    # --- AWS-managed: Signature-based (higher capacity but high value) ---
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/ThreatSignaturesIOCActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/ThreatSignaturesPhishingActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${var.region}:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareCoinminingActionOrder"
    }
  }
  tags = var.tags
}

resource "aws_networkfirewall_firewall" "fw" {
  name                = "trafinspector-fw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.policy.arn
  vpc_id              = aws_vpc.inspection.id
  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall[*].id
    content { subnet_id = subnet_mapping.value }
  }
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "nfw" {
  for_each          = toset(["flow", "alert", "tls"])
  name              = "/trafinspector/nfw/${each.key}"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_networkfirewall_logging_configuration" "logs" {
  firewall_arn = aws_networkfirewall_firewall.fw.arn
  logging_configuration {
    dynamic "log_destination_config" {
      for_each = aws_cloudwatch_log_group.nfw
      content {
        log_type             = upper(log_destination_config.key)
        log_destination_type = "CloudWatchLogs"
        log_destination      = { logGroup = log_destination_config.value.name }
      }
    }
  }
}
