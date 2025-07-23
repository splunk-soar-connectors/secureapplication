The Secure Application connector supports only the cloud-based version of Secure Application. On-prem deployments are not supported.

Ensure you have registered an API client in your AppDynamics Controller tenant with the appropriate permissions to execute the public APIs for Secure Application triggered from the SOAR platform.

Ensure you have the following credentials available from your Secure Application console:
Client Name – Unique identifier for the API client
Client Secret – Secret string used for authentication

Provide the following information in the asset configuration:

API Key:
The client ID of your AppDynamics API client
Example: master-admin

API Key Secret:
The secret associated with the API client
Example: 89hsooo768890!

Base URL:
The full URL of your AppDynamics Controller instance
Example: https://secureapp-master.cisco.com/

Account ID:
Account name, first part of the Base URL hostname
Example: secureapp-master

The SOAR connector for Secure Application will use the provided API key and secret to obtain an OAuth 2.0 access token from AppDynamics Controller. This token is used for all authenticated API requests and is automatically refreshed when expired.

Click Test Connectivity to validate the asset configuration by authenticating with the controller and confirming access to Secure Application.

Click Save to store the configuration.

Secure Application API Docs for Reference:
https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/25.7.0/extend-splunk-appdynamics/splunk-appdynamics-apis/cisco-secure-application-apis

Version: 25.7.0


