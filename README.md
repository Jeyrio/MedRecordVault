# MedRecordVault

A secure, blockchain-based medical records management system built on the Stacks blockchain.

## Overview

MedRecordVault provides a decentralized solution for storing and managing access to sensitive medical records. The system ensures that only authorized healthcare providers can access patient data, with time-limited permissions and complete audit trails.

## Features

- Secure storage of medical record hashes on the blockchain
- Granular access control for healthcare providers
- Time-limited authorizations
- Complete audit trail of all access requests
- Patient-controlled permissions

## Smart Contract Functions

- `add-record`: Add a new patient record to the system
- `grant-access`: Allow a healthcare provider to access a patient's records
- `check-access`: Verify if a provider has access to a specific patient's records
- `revoke-access`: Remove a provider's access to patient records
- `get-record`: Retrieve a patient's record (only if authorized)

## Getting Started

1. Clone this repository
2. Install Clarinet: `npm install -g @stacks/clarinet`
3. Run tests: `clarinet test`

## Security Considerations

- The contract stores only hashes of medical records, not the actual data
- Access control is enforced at the contract level
- Time-limited permissions reduce risk of unauthorized access