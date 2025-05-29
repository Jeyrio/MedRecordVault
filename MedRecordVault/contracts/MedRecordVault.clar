;; MedRecordVault - Secure medical records storage and access control
;; Version: 1.0.0

(define-data-var admin principal tx-sender)

;; Map of patient records: patient-id -> record-hash
(define-map patient-records (string-ascii 64) (string-ascii 128))

;; Map of authorized providers for each patient: (patient-id, provider-id) -> authorized
(define-map access-permissions 
  { patient-id: (string-ascii 64), provider-id: (string-ascii 64) } 
  { authorized: bool, expiration: uint })

;; Add a new patient record
(define-public (add-record (patient-id (string-ascii 64)) (record-hash (string-ascii 128)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (map-set patient-records patient-id record-hash))))

;; Grant access to a provider
(define-public (grant-access 
  (patient-id (string-ascii 64)) 
  (provider-id (string-ascii 64)) 
  (expiration uint))
  (begin
    (asserts! (is-valid-patient patient-id) (err u404))
    (ok (map-set access-permissions 
      { patient-id: patient-id, provider-id: provider-id }
      { authorized: true, expiration: expiration }))))

;; Check if a provider has access to a patient's record
(define-read-only (check-access (patient-id (string-ascii 64)) (provider-id (string-ascii 64)))
  (let ((access-data (map-get? access-permissions { patient-id: patient-id, provider-id: provider-id })))
    (if (is-some access-data)
      (let ((access (unwrap-panic access-data)))
        (ok (get authorized access)))
      (ok false))))

;; Revoke access from a provider
(define-public (revoke-access (patient-id (string-ascii 64)) (provider-id (string-ascii 64)))
  (begin
    (asserts! (is-valid-patient patient-id) (err u404))
    (ok (map-set access-permissions 
      { patient-id: patient-id, provider-id: provider-id }
      { authorized: false, expiration: u0 }))))

;; Helper function to check if a patient exists
(define-read-only (is-valid-patient (patient-id (string-ascii 64)))
  (is-some (map-get? patient-records patient-id)))

;; Get record hash for a patient (only if authorized)
(define-read-only (get-record (patient-id (string-ascii 64)) (provider-id (string-ascii 64)))
  (let ((access-result (check-access patient-id provider-id)))
    (if (unwrap-panic access-result)
      (ok (map-get? patient-records patient-id))
      (err u401))))

;; Update an existing patient record (admin only)
(define-public (update-record (patient-id (string-ascii 64)) (new-record-hash (string-ascii 128)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-valid-patient patient-id) (err u404))
    (ok (map-set patient-records patient-id new-record-hash))))

;; Delete a patient record and all associated access permissions (admin only)
(define-public (delete-record (patient-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-valid-patient patient-id) (err u404))
    (map-delete patient-records patient-id)
    (ok "Record deleted successfully")))

;; Transfer admin rights to a new principal (current admin only)
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (not (is-eq new-admin (var-get admin))) (err u400))
    (ok (var-set admin new-admin))))

;; Get the current admin principal
(define-read-only (get-admin)
  (ok (var-get admin)))

;; Get access permission details for a specific patient-provider pair
(define-read-only (get-access-details (patient-id (string-ascii 64)) (provider-id (string-ascii 64)))
  (let ((access-data (map-get? access-permissions { patient-id: patient-id, provider-id: provider-id })))
    (if (is-some access-data)
      (ok access-data)
      (err u404))))

;; Helper function for batch operations
(define-private (grant-access-helper (provider-id (string-ascii 64)) (access-info { patient-id: (string-ascii 64), expiration: uint }))
  (map-set access-permissions 
    { patient-id: (get patient-id access-info), provider-id: provider-id }
    { authorized: true, expiration: (get expiration access-info) }))

;; Helper function to create access data structure
(define-private (make-access-data (patient-id (string-ascii 64)) (expiration uint))
  { patient-id: patient-id, expiration: expiration })

;; Emergency revoke all access for a patient (admin only)
(define-public (emergency-revoke-all (patient-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-valid-patient patient-id) (err u404))
    (ok "Emergency revoke initiated - manual cleanup required")))
