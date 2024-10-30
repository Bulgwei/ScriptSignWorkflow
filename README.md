# ScriptSignWorkflow
Secure and centralized workflow to sign PoS scripts

ScriptWorkflow provides a secure and centralized way of submitting signature requests for PoS scripts. The workflow consists of a scheduled task that will run periodically, referred to as Agent later in the documentation. 

•	Signature Agent (SignatureAgnt.ps1)

The signature agent is looking into a filesystem (CIFs)-based inbox and submits the content (PoS scripts) to a central signature system (which owns the code signing certificate and key material). Here, the submitted script stay pending and waiting for manual verification and approval (recommended) or (configuration-based) the approval is automatically enforced.

When a submission has been approved, the signed scripts are ready for collection from a (CIFs)-based outbox.
The installation of the agent and the configuration is based on a XML-configuration file.
