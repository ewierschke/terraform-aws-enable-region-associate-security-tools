variable "project_name" {
  description = "Project name to prefix resources with"
  type        = string
}

variable "assume_role_name" {
  description = "Name of the IAM role that the lambda will assume in the security tooling account"
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "enable_detective" {
  description = "Boolean toggle to control whether to enable Detective"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Boolean toggle to control whether to enable GuardDuty"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Boolean toggle to control whether to enable Inspector"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Boolean toggle to control whether to enable Macie"
  type        = bool
  default     = true
}

variable "event_bus_name" {
  description = "Event bus name to create event rules in"
  type        = string
  default     = "default"
}

variable "event_types" {
  description = "Event types that will trigger this lambda"
  type        = set(string)
  default = [
    "EnableOptInRegion"
  ]

  validation {
    condition = alltrue([for event in var.event_types : contains(
      [
        "EnableOptInRegion"
      ],
      event
    )])
    error_message = "Supported event_types include only: EnableOptInRegion"
  }
}

variable "dry_run" {
  description = "Boolean toggle to control the dry-run mode of the lambda function"
  type        = bool
  default     = true
}

variable "lambda" {
  description = "Object of optional attributes passed on to the lambda module"
  type = object({
    artifacts_dir            = optional(string, "builds")
    build_in_docker          = optional(bool, false)
    create_package           = optional(bool, true)
    ephemeral_storage_size   = optional(number)
    ignore_source_code_hash  = optional(bool, true)
    local_existing_package   = optional(string)
    memory_size              = optional(number, 128)
    recreate_missing_package = optional(bool, false)
    runtime                  = optional(string, "python3.12")
    s3_bucket                = optional(string)
    s3_existing_package      = optional(map(string))
    s3_prefix                = optional(string)
    store_on_s3              = optional(bool, false)
    timeout                  = optional(number, 300)
  })
  default = {}
}

variable "log_level" {
  description = "Log level for lambda"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], var.log_level)
    error_message = "Valid values for log level are (CRITICAL, ERROR, WARNING, INFO, DEBUG)."
  }
}

variable "max_workers" {
  description = "Number of worker threads to use to process delete"
  type        = number
  default     = 20
}

variable "aws_sts_regional_endpoints" {
  description = "Sets AWS STS endpoint resolution logic for boto3."
  type        = string
  default     = "regional"
  validation {
    condition     = contains(["regional", "legacy"], var.aws_sts_regional_endpoints)
    error_message = "Valid values for aws sts regional endpoints are (regional, legacy)."
  }
}

variable "security_tooling_account_id" {
  description = "Security Tooling Account ID"
  type        = string
  validation {
    condition = (
      length(var.security_tooling_account_id) == 12
    )
    error_message = "The \"security_tooling_account_id\" must be a 12-character numeric string."
  }
}

variable "tags" {
  description = "Tags for resource"
  type        = map(string)
  default     = {}
}
