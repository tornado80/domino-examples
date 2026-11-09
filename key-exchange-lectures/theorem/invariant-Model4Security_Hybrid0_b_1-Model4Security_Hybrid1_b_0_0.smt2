;; Hop 2: Model4Security_Hybrid0_b_1 == Model4Security_Hybrid1_b_0_0.
;; The collision aborts move from KEMCollisions into KEMReductionIndCca, and
;; the real KEM moves into KEMIndCca with b_ind false. The protocol, model and
;; MAC packages are the same on both sides.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "MACMultiKey" "MAC_Gen" "psk"))
         (= sample-id-right (sample-id "MACMultiKey" "MAC_Gen" "psk"))))

(define-fun randomness-mapping-Corrupt
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-NewSession
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send1
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMCollisions" "Coll_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMIndCca" "Ind_Gen" "kem_kgen"))))

;; Both sides branch on whether the public key is honest, so the mapping is
;; static: honest branch to honest branch, local branch to local branch.
(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (or (and (= sample-id-left (sample-id "KEMCollisions" "Coll_Encaps" "kem_encaps"))
                  (= sample-id-right (sample-id "KEMIndCca" "Ind_Encaps" "kem_encaps")))
             (and (= sample-id-left (sample-id "KEMReductionCollisions" "KEM_Encaps" "kem_encaps"))
                  (= sample-id-right (sample-id "KEMReductionIndCca" "KEM_Encaps" "kem_encaps"))))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send4
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Reveal
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Test
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "Model4Modular" "Test" "test"))
         (= sample-id-right (sample-id "Model4Modular" "Test" "test"))))

;; The packages above the KEM are literally the same.
(define-state-relation upper-packages-equal (l r)
    (and (= l.Model4Modular r.Model4Modular)
         (= l.MACMultiKey r.MACMultiKey)))

;; Key pairs and shared keys.
(define-state-relation kem-tables-equal (l r)
    (and (= l.KEMReductionCollisions.hk_ctr r.KEMIndCca.ctr)
         (= l.KEMReductionCollisions.h_ctr r.KEMReductionIndCca.h_ctr)
         (= l.KEMReductionCollisions.PK r.KEMIndCca.PK)
         (= l.KEMReductionCollisions.SK r.KEMIndCca.SK)
         (= l.KEMReductionCollisions.Key r.KEMReductionIndCca.Key)
         (= l.KEMReductionCollisions.Valid r.KEMReductionIndCca.Valid)))

(define-state-relation pk-bound (l r)
    (forall ((hk Int))
        (=> (> hk r.KEMIndCca.ctr)
            ((_ is mk-none) (select r.KEMIndCca.PK hk)))))

;; The three notions of "honest public key" agree, and the right table maps a
;; public key to a key handle holding that public key.
(define-state-relation hon-agree (l r)
    (and (= l.KEMCollisions.Hon l.KEMReductionCollisions.Hon)
         (forall ((pk Bits_lpk))
             (let ((e (select r.KEMReductionIndCca.Hon pk)))
                 (and (= ((_ is mk-some) (select l.KEMReductionCollisions.Hon pk))
                         ((_ is mk-some) e))
                      (=> ((_ is mk-some) e)
                          (= (select r.KEMIndCca.PK (maybe-get e)) (mk-some pk))))))))

;; Used public keys are the honest ones and the ones already encapsulated to.
(define-state-relation used-pk (l r)
    (forall ((pk Bits_lpk))
        (= ((_ is mk-some) (select l.KEMCollisions.UsedPk pk))
           (or ((_ is mk-some) (select r.KEMReductionIndCca.Hon pk))
               ((_ is mk-some) (select r.KEMReductionIndCca.Seen pk))))))

(define-state-relation used-ct (l r)
    (= l.KEMCollisions.UsedCt r.KEMReductionIndCca.HC))

(define-state-relation invariant (l r)
    (and (upper-packages-equal l r)
         (kem-tables-equal l r)
         (pk-bound l r)
         (hon-agree l r)
         (used-pk l r)
         (used-ct l r)))
