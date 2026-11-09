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

;; The left side always encapsulates in Coll_Encaps. The right side does so
;; in Ind_Encaps for an honest public key and locally otherwise, so the mapping
;; reads the old state.
(define-state-relation send2-pk-honest (l r)
    ((_ is mk-some) (select r.KEMReductionIndCca.Hon <arg-Model4Security_Hybrid1-Send2-m1>)))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMCollisions" "Coll_Encaps" "kem_encaps"))
         (ite (send2-pk-honest <<game-state-Model4Security_Hybrid0_b_1-old>> <<game-state-Model4Security_Hybrid1_b_0_0-old>>)
              (= sample-id-right (sample-id "KEMIndCca" "Ind_Encaps" "kem_encaps"))
              (= sample-id-right (sample-id "KEMReductionIndCca" "KEM_Encaps" "kem_encaps")))))

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
    (and (= l.KEMReductionCollisions.hk_ctr r.KEMReductionIndCca.hk_ctr)
         (= l.KEMReductionCollisions.h_ctr r.KEMReductionIndCca.h_ctr)
         (= l.KEMReductionCollisions.PK r.KEMReductionIndCca.PK)
         (= l.KEMReductionCollisions.Key r.KEMReductionIndCca.Key)
         (= l.KEMReductionCollisions.Valid r.KEMReductionIndCca.Valid)))

(define-state-relation hon-equal (l r)
    (= l.KEMCollisions.Hon r.KEMReductionIndCca.Hon))

(define-state-relation pk-bound (l r)
    (forall ((hk Int))
        (=> (> hk r.KEMReductionIndCca.hk_ctr)
            (and ((_ is mk-none) (select r.KEMReductionIndCca.PK hk))
                 ((_ is mk-none) (select l.KEMReductionCollisions.SK hk))))))

;; Left SK is indexed by handle and right SK by public key. They agree because
;; every allocated handle holds an honest public key, and the Gen aborts stop
;; an honest public key from being generated again.
(define-state-relation sk-agree (l r)
    (forall ((hk Int))
        (let ((p (select r.KEMReductionIndCca.PK hk)))
            (and (= ((_ is mk-none) p)
                    ((_ is mk-none) (select l.KEMReductionCollisions.SK hk)))
                 (=> ((_ is mk-some) p)
                     (and ((_ is mk-some) (select r.KEMReductionIndCca.Hon (maybe-get p)))
                          (= (select r.KEMIndCca.SK (maybe-get p))
                             (select l.KEMReductionCollisions.SK hk))))))))

;; Ind_Encaps requires a generated public key.
(define-state-relation hon-has-sk (l r)
    (forall ((pk Bits_lpk))
        (=> ((_ is mk-some) (select r.KEMReductionIndCca.Hon pk))
            ((_ is mk-some) (select r.KEMIndCca.SK pk)))))

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
         (hon-equal l r)
         (pk-bound l r)
         (sk-agree l r)
         (hon-has-sk l r)
         (used-pk l r)
         (used-ct l r)))
