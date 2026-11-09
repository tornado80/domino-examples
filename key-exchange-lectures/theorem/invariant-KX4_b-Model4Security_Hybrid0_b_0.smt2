;; Hop 0: KX4_b == Model4Security_Hybrid0_b_0.
;; Pure refactoring. The right game holds kid instead of psk and integer
;; handles instead of sk_fs and shk_fs. The left values are the ones stored
;; under those handles on the right.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (or (and (= sample-id-left (sample-id "Model4" "NewKey" "psk"))
                  (= sample-id-right (sample-id "MACMultiKey" "MAC_Gen" "psk"))))))

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
         (or (and (= sample-id-left (sample-id "KEM" "KEM_Gen" "kem_kgen"))
                  (= sample-id-right (sample-id "KEMCollisions" "Coll_Gen" "kem_kgen"))))))

;; Send2 has one encapsulation sample on the left and two on the right, one
;; per branch of KEMReductionCollisions.KEM_Encaps. The branch taken depends on
;; whether the public key is honest, so the mapping reads the old state.
(define-state-relation send2-pk-honest (l r)
    ((_ is mk-some) (select r.KEMReductionCollisions.Hon <arg-Model4Security_Hybrid0-Send2-m1>)))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEM" "KEM_Encaps" "kem_encaps"))
         (ite (send2-pk-honest <<game-state-KX4_b-old>> <<game-state-Model4Security_Hybrid0_b_0-old>>)
              (= sample-id-right (sample-id "KEMCollisions" "Coll_Encaps" "kem_encaps"))
              (= sample-id-right (sample-id "KEMReductionCollisions" "KEM_Encaps" "kem_encaps")))))

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
         (or (and (= sample-id-left (sample-id "Model4" "Test" "test"))
                  (= sample-id-right (sample-id "Model4Modular" "Test" "test"))))))

;; Counters and the tables that are copied literally.
(define-state-relation counters-equal (l r)
    (and (= l.Model4.ctr_ r.Model4Modular.ctr_)
         (= l.Model4.kid_ r.MACMultiKey.kid_ctr)))

(define-state-relation model-tables-equal (l r)
    (and (= l.Model4.C r.Model4Modular.C)
         (= l.Model4.KID r.Model4Modular.KID)
         (= l.Model4.Fresh r.Model4Modular.Fresh)
         (= l.Model4.TR r.Model4Modular.TR)))

;; psk: the left PSK table is the MAC key table, and the right PSK table is
;; the identity on allocated key ids.
(define-state-relation psk-tables (l r)
    (and (= l.Model4.PSK r.MACMultiKey.K)
         (forall ((kid Int))
             (ite ((_ is mk-none) (select r.MACMultiKey.K kid))
                  ((_ is mk-none) (select r.Model4Modular.PSK kid))
                  (= (select r.Model4Modular.PSK kid) (mk-some kid))))))

;; Allocation bounds: nothing is stored beyond the counters, so a newly
;; allocated handle never overwrites a stored value.
(define-state-relation kid-bound (l r)
    (forall ((kid Int))
        (=> (> kid r.MACMultiKey.kid_ctr)
            ((_ is mk-none) (select r.MACMultiKey.K kid)))))

(define-state-relation handle-bound (l r)
    (forall ((h Int))
        (=> (> h r.KEMReductionCollisions.h_ctr)
            ((_ is mk-none) (select r.KEMReductionCollisions.Key h)))))

(define-state-relation keypair-bound (l r)
    (forall ((hk Int))
        (and (=> (> hk r.KEMReductionCollisions.hk_ctr)
                 ((_ is mk-none) (select r.KEMReductionCollisions.SK hk)))
             (=> ((_ is mk-some) (select r.KEMReductionCollisions.SK hk))
                 ((_ is mk-some) (select r.KEMReductionCollisions.PK hk))))))

;; KEMCollisions gives Coll_Encaps an honest public key exactly when the
;; reduction thinks it is honest.
(define-state-relation hon-tables-equal (l r)
    (= r.KEMCollisions.Hon r.KEMReductionCollisions.Hon))

;; Sessions, field by field.
(define-state-relation sessions-related (l r)
    (forall ((ctr Int))
        (let ((sl (select l.Model4.State ctr))
              (sr (select r.Model4Modular.State ctr)))
            (and
                (= ((_ is mk-none) sl) ((_ is mk-none) sr))
                (=> ((_ is mk-some) sl)
                    (let ((tl (maybe-get sl))
                          (tr (maybe-get sr)))
                        (let ((kL (el8-6 tl))
                              (kR (el8-6 tr))
                              (oL (el8-7 tl))
                              (oR (el8-7 tr)))
                            (and
                                (= (el8-1 tl) (el8-1 tr))
                                (= (select r.MACMultiKey.K (el8-2 tr)) (mk-some (el8-2 tl)))
                                (= (el8-3 tl) (el8-3 tr))
                                (= (el8-4 tl) (el8-4 tr))
                                (= (el8-5 tl) (el8-5 tr))
                                (= (el8-8 tl) (el8-8 tr))
                                (= ((_ is mk-none) kL) ((_ is mk-none) kR))
                                (=> ((_ is mk-some) kL)
                                    (and ((_ is mk-some) (select r.KEMReductionCollisions.Valid (maybe-get kR)))
                                         (= (select r.KEMReductionCollisions.Key (maybe-get kR))
                                            (mk-some (maybe-get kL)))))
                                (= ((_ is mk-none) oL) ((_ is mk-none) oR))
                                (=> ((_ is mk-some) oL)
                                    (let ((skL (el2-1 (maybe-get oL)))
                                          (hkR (el2-1 (maybe-get oR)))
                                          (shkL (el2-2 (maybe-get oL)))
                                          (hR (el2-2 (maybe-get oR))))
                                        (and
                                            (= ((_ is mk-none) skL) ((_ is mk-none) hkR))
                                            (=> ((_ is mk-some) skL)
                                                (= (select r.KEMReductionCollisions.SK (maybe-get hkR))
                                                   (mk-some (maybe-get skL))))
                                            (= ((_ is mk-none) shkL) ((_ is mk-none) hR))
                                            (=> ((_ is mk-some) shkL)
                                                (and ((_ is mk-some) (select r.KEMReductionCollisions.Valid (maybe-get hR)))
                                                     (= (select r.KEMReductionCollisions.Key (maybe-get hR))
                                                        (mk-some (maybe-get shkL))))))))))))))))

(define-state-relation invariant (l r)
    (and (counters-equal l r)
         (model-tables-equal l r)
         (psk-tables l r)
         (kid-bound l r)
         (handle-bound l r)
         (keypair-bound l r)
         (hon-tables-equal l r)
         (sessions-related l r)))
