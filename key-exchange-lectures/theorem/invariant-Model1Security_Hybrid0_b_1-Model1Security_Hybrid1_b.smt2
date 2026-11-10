;; Hop 2: Model1Security_Hybrid0_b_1 == Model1Security_Hybrid1_b.
;; The left sessions hold the secret key, the shared key and the session key.
;; The right sessions hold none of them: KEMPrf computes the session key from
;; (pk, c, nc) when it is revealed or tested. The collision aborts stop an
;; initiator's entry in S from being overwritten.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMCollisions" "Coll_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMPrf" "KP_Gen" "kem_kgen"))))

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
         (= sample-id-left (sample-id "KEMCollisions" "Coll_Encaps" "kem_encaps"))
         (= sample-id-right (sample-id "KEMPrf" "KP_Encaps" "kem_encaps"))))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "Prot1" "Run2" "nc"))
         (= sample-id-right (sample-id "Prot1Modular" "Run2" "nc"))))

(define-fun randomness-mapping-Send3
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
         (= sample-id-left (sample-id "Model1" "Test" "test"))
         (= sample-id-right (sample-id "KEMPrf" "KP_Test" "test"))))

;; Counters and the tables that are copied literally.
(define-state-relation tables-equal (l r)
    (and (= l.Model1.ctr_ r.Model1Modular.ctr_)
         (= l.Model1.C r.KEMPrf.C)
         (= l.Model1.T r.KEMPrf.T)
         (= l.Model1.SK r.KEMPrf.SK)
         (= l.Model1.TR r.Model1Modular.TR)
         (= l.KEMCollisions.Hon r.KEMReductionPrf.Hon)
         (= l.KEMCollisions.UsedCt r.KEMReductionPrf.HC)))

;; Registered, honest and used public keys are the generated ones.
(define-state-relation keys-registered (l r)
    (forall ((pk Bits_lpk))
        (and (= ((_ is mk-some) (select r.Model1Modular.Reg pk))
                ((_ is mk-some) (select r.KEMPrf.SK pk)))
             (= ((_ is mk-some) (select r.KEMReductionPrf.Hon pk))
                ((_ is mk-some) (select r.KEMPrf.SK pk)))
             (= ((_ is mk-some) (select l.KEMCollisions.UsedPk pk))
                ((_ is mk-some) (select r.KEMPrf.SK pk))))))

;; Every shared key stored in KEMPrf comes from an encapsulation that passed
;; the collision check.
(define-state-relation shared-keys-registered (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (= ((_ is mk-some) (select r.KEMReductionPrf.HC (mk-tuple2 pk c)))
           ((_ is mk-some) (select r.KEMPrf.S (mk-tuple2 pk c))))))

;; A triple can only be used in KEMPrf after its pair was marked in the model,
;; so the KEMPrf restriction never fires on its own.
(define-state-relation tr-covered (l r)
    (forall ((pk Bits_lpk) (c Bits_lct) (x Bits_lnonce))
        (=> ((_ is mk-some) (select r.KEMPrf.TR (mk-tuple3 pk c x)))
            ((_ is mk-some) (select r.Model1Modular.TR (mk-tuple2 c x))))))

;; Nothing is stored beyond the session counter.
(define-state-relation session-bound (l r)
    (forall ((ctr Int))
        (=> (> ctr r.Model1Modular.ctr_)
            (and ((_ is mk-none) (select l.Model1.State ctr))
                 ((_ is mk-none) (select r.Model1Modular.State ctr))))))

;; Sessions, field by field.
(define-state-relation sessions-related (l r)
    (forall ((ctr Int))
        (let ((sl (select l.Model1.State ctr))
              (sr (select r.Model1Modular.State ctr)))
            (and
                (= ((_ is mk-none) sl) ((_ is mk-none) sr))
                (=> ((_ is mk-some) sl)
                    (let ((tl (maybe-get sl))
                          (tr (maybe-get sr)))
                        (let ((role (el8-1 tl))
                              (pk (el8-2 tl))
                              (sk (el8-3 tl))
                              (m1 (el8-4 tl))
                              (m2 (el8-5 tl))
                              (k (el8-6 tl))
                              (other (el8-7 tl))
                              (acc (el8-8 tl)))
                            (and
                                (= role (el5-1 tr))
                                (= pk (el5-2 tr))
                                (= m1 (el5-3 tr))
                                (= m2 (el5-4 tr))
                                (= acc (el5-5 tr))
                                ((_ is mk-some) (select r.KEMPrf.SK pk))
                                (=> (not role) ((_ is mk-none) sk))
                                (=> role (= sk (select r.KEMPrf.SK pk)))
                                (=> (and (not role) ((_ is mk-some) m1))
                                    (and ((_ is mk-some) other)
                                         ((_ is mk-some) (select r.KEMReductionPrf.HC (mk-tuple2 pk (maybe-get m1))))
                                         (= other (select r.KEMPrf.S (mk-tuple2 pk (maybe-get m1))))))
                                (=> (= acc (mk-some true))
                                    (and ((_ is mk-some) m1)
                                         ((_ is mk-some) m2)
                                         (= k (mk-some
                                                 (ite role
                                                      (l.prf (l.kem_decaps (maybe-get sk) (maybe-get m1)) (maybe-get m2))
                                                      (l.prf (maybe-get other) (maybe-get m2)))))))))))))))

(define-state-relation invariant (l r)
    (and (tables-equal l r)
         (keys-registered l r)
         (shared-keys-registered l r)
         (tr-covered l r)
         (session-bound l r)
         (sessions-related l r)))
