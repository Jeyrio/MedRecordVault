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
        (if (and (get authorized access) (< block-height (get expiration access)))
          (ok true)
          (ok false)))
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
      