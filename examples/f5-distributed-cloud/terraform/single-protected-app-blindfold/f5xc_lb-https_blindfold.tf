# Health Check

resource "volterra_healthcheck" "http-health-check" {
  name                   = "http-health-check"
  namespace              = var.namespace
  http_health_check {
    use_origin_server_name = true
    path                   = "/"
  }
  healthy_threshold   = 2
  interval            = 5
  timeout             = 1
  unhealthy_threshold = 5
}

# Origin Pool

resource "volterra_origin_pool" "http-origin-pool" {
  name                   = "http-origin-pool"
  namespace              = var.namespace
   origin_servers {
    public_name {
      dns_name = var.origin_server_dns
    }
    labels = {
    }
  }
  no_tls = true
  port = "80"
  endpoint_selection     = "LOCALPREFERED"
  loadbalancer_algorithm = "LB_OVERRIDE"
  healthcheck {
    name = volterra_healthcheck.http-health-check.name
  }
}

# App Firewall

resource "volterra_app_firewall" "appfw" {
  name      = "appfw"
  namespace = var.namespace

  allow_all_response_codes = true
  default_anonymization = true
  use_default_blocking_page = true
  default_bot_setting = true
  default_detection_settings = true
  use_loadbalancer_setting = true
  blocking = true
}

# Load-Balancer

 resource "volterra_http_loadbalancer" "https-lb" {
  depends_on = [volterra_origin_pool.http-origin-pool]
  name      = "https-lb"
  namespace = var.namespace
  domains = [ var.app_domain ]
   https {
    port = "443"
    add_hsts = true
    http_redirect = true
    enable_path_normalize = true
    tls_parameters {
      no_mtls = true
      tls_config {
        default_security = true  
      }
      tls_certificates {
        # Use the Base64 certificate generated by the blindfold.sh script
        certificate_url  = "${(local.blindfoldb64[0])}"
        private_key {
          blindfold_secret_info {
             decryption_provider = ""
             store_provider = ""
             # Use the Blindfold secret generated by the blindfold.sh script
             location = "${(local.blindfoldb64[1])}"
          }
          secret_encoding_type = "EncodingNone"
        }
      }    
    }
  }
  default_route_pools {
      pool {
        name = "http-origin-pool"
        namespace = var.namespace
      }
      weight = 1
    }
  advertise_on_public_default_vip = true
  no_service_policies = true
  no_challenge = true
  disable_rate_limit = true
  app_firewall {
    name = "appfw"
    namespace = var.namespace
  }
  multi_lb_app = true
  user_id_client_ip = true
  source_ip_stickiness = true
}
