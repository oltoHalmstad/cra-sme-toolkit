# Related work: verified bibliography mapped to RQs and experiments

Compiled on 17 Oct 2026. Each entry was checked against a publisher, DOI, arXiv or institutional page; anything not fully confirmed is marked ⚠. **This is not yet a systematic review.** Use it to seed the Phase 1 search protocol.

## CRA-specific
- Chiara, P. G. (2022). The Cyber Resilience Act: the EU Commission's proposal… *International Cybersecurity Law Review*. ⚠ DOI probably 10.1365/s43439-022-00067-6; check before citing. Relevant to: RQ1 background.
- Ruohonen, J., & Timmers, P. (2024/25). Vulnerability Coordination Under the Cyber Resilience Act. arXiv:2412.06261; DOI 10.60097/ACIG/213350. Relevant to: RQ1, E5.
- Ruohonen, J., Hjerppe, K., & Kang, E.-Y. (2025). A Mapping Analysis of Requirements Between the CRA and the GDPR. *IEEE REW 2025*, 215–222. DOI 10.1109/REW66121.2025.00034. Relevant to: RQ1.
- Ruohonen, J., Tuli, E. A., & Morita, H. (2026). Compliance as Code: A Study of Linux Distributions and Beyond. arXiv:2603.01520. Maps about 1,500 rules to CRA essential requirements and reports only modest agreement between mappers. Relevant to: RQ1, RQ3.
- Teichmann, F. (2025). The cyber resilience act as a new paradigm for product security: a compliance roadmap. *ICLR* 7(1). DOI 10.1365/s43439-025-00162-4. Relevant to: RQ1.
- **Koutidis, G., et al. (2026).** Preparing an AI-Augmented SIEM for the EU CRA: A Practitioner Case Study. arXiv:2610.07873. **Closest competing work.** Relevant to: RQ1, RQ4.
- Szedlak, C., Reinemann, H., & Hatzelmann, S. (2024). Assessing SME Awareness and Preparedness for the CRA. *IEOM*. DOI 10.46254/ap05.20240160. 12.3% of SMEs were aware of the CRA. Relevant to: RQ5.
- ENISA (2026). SME CRA Survey Report (24 Jun 2026). ⚠ Only the landing page was read. Relevant to: RQ5.
- Lawson, A., & Hendrick, S. (2025). Unaware and Uncertain: CRA Readiness in Open Source. Linux Foundation Research. Relevant to: RQ5.

## Compliance engineering and traceability
- Breaux, T. D., & Antón, A. I. (2008). Analyzing Regulatory Rules for Privacy and Security Requirements. *IEEE TSE* 34(1). DOI 10.1109/TSE.2007.70746. Relevant to: RQ1 method.
- Akhigbe, O., Amyot, D., & Richards, G. (2019). Systematic literature mapping of modelling methods for legal compliance. *Requirements Engineering* 24. DOI 10.1007/s00766-018-0294-1. Relevant to: RQ1.
- Usman, M., et al. (2020). Compliance Requirements in Large-Scale Software Development: An Industrial Case Study. arXiv:2103.01821. Relevant to: RQ1, RQ5.
- Kellogg, M., Schäf, M., Tasiran, S., & Ernst, M. D. (2020). Continuous Compliance. *ASE '20*. DOI 10.1145/3324884.3416593. Relevant to: RQ2, RQ4.
- Moyón, F., et al. (2020). Integration of security standards in DevOps pipelines. *PROFES 2020*. DOI 10.1007/978-3-030-64148-1_27. Relevant to: RQ1, RQ2.
- Moyón, F., et al. (2026). Aligning Security Compliance and DevOps: A Longitudinal Study. *JSS* 234, 112718. DOI 10.1016/j.jss.2025.112718. Relevant to: RQ1, RQ5; a DSR template.
- Antoniol, G., et al. (2017). Grand Challenges of Traceability. arXiv:1710.03129. Relevant to: RQ1, RQ4.
- Regan, G., Flood, D., & Mc Caffery, F. (2016). Industrial trial of a traceability assessment framework. *ICSSP '16*. Relevant to: RQ1, RQ4.
- Horstmann, S. A., et al. (2025). "Sorry for bugging you so much." *IEEE S&P 2025*. DOI 10.1109/SP61157.2025.00146. Relevant to: RQ2; shows guidance alone does not work.
- Torres-Arias, S., et al. (2019). in-toto. *USENIX Security '19*. Relevant to: RQ4 provenance.

## SBOM
- Stalnaker, T., et al. (2024). BOMs Away! *ICSE 2024*. DOI 10.1145/3597503.3623347. Relevant to: RQ4, RQ5.
- Xia, B., et al. (2023). An Empirical Study on SBOM. *ICSE 2023*. arXiv:2301.05362. Relevant to: RQ4, RQ5.
- O'Donoghue, E., et al. (2024). Impacts of SBOM Generation on Vulnerability Detection. *SCORED '24*. ⚠ DOI unconfirmed. **Design template for E1.**
- Benedetti, G., et al. (2024). Impact of SBOM Generators on Vulnerability Assessment in Python. arXiv:2409.06390. Relevant to: E1.
- Balliu, M., et al. (2023). Challenges of Producing SBOM for Java. *IEEE S&P Magazine*. DOI 10.1109/MSEC.2023.3302956. Its data is in github.com/chains-project/sbom-2023, a **reusable E1 ground truth**.
- Mirakhorli, M., et al. (2024). Landscape Study of SBOM Tools. arXiv:2402.11151. Relevant to: E1 tool selection.
- Zhou, L., Dacier, M., & Konstantinou, C. (2025/26). A Reality Check on SBOM-based Vulnerability Management. arXiv:2511.20313. Reports a scanner false-positive rate of about 92%. Relevant to: E2 (H2b).
- O'Donoghue, E., et al. (2025). SBOM in Software Supply Chain Security: SLR. arXiv:2506.03507. Relevant to: RQ4, RQ5.
- Okhravi, H., Burow, N., & Schneider, F. B. (2025). SBOM as a Proactive Defense. *IEEE S&P Magazine*. DOI 10.1109/MSEC.2025.3528535. Relevant to: RQ4.

## Scanner disagreement
- Imtiaz, N., Thorne, S., & Williams, L. (2021). Comparative Study of Vulnerability Reporting by SCA Tools. *ESEM '21*. DOI 10.1145/3475716.3475769. Relevant to: E2.
- Zhao, L., et al. (2023). SCA for Vulnerability Detection: An Empirical Study on Java. *ESEC/FSE 2023*. DOI 10.1145/3611643.3616299. Relevant to: E2.
- Boles, B., et al. (2024). Deciphering Discrepancies: Docker Image Security. *IEEE SCAM 2024*. Relevant to: E2.
- Ponta, S. E., Plate, H., & Sabetta, A. (2020). Detection, assessment and mitigation of vulnerabilities in OSS dependencies. *EMSE*. DOI 10.1007/s10664-020-09830-x. Relevant to: E2.
- Mandl, P., et al. (2026). Ground-Truth-Based Evaluation of Vulnerability Detection Across Ecosystems. arXiv:2604.21111. A **benchmark for E2**.
- Zahan, N., et al. (2023). OpenSSF Scorecard. *IEEE S&P Magazine*. DOI 10.1109/MSEC.2023.3279773. Relevant to: RQ4.

## Risk scoring
- Cox, L. A. (2008). What's Wrong with Risk Matrices? *Risk Analysis* 28(2). DOI 10.1111/j.1539-6924.2008.01030.x. Relevant to: RQ3, F-04.
- Hubbard, D. W., & Seiersen, R. (2023). *How to Measure Anything in Cybersecurity Risk* (2nd ed.). Wiley. Relevant to: E3 condition C, calibration.
- The Open Group. O-RA v2.0.1 / O-RT v3.0.1 (Open FAIR). Relevant to: E3 condition C.
- Jacobs, J., et al. (2019). EPSS. arXiv:1908.04856; Jacobs, J., et al. (2023). EPSS v3. arXiv:2302.14172. Relevant to: RQ3 inputs.
- Spring, J. M., et al. (2021). Time to Change the CVSS? *IEEE S&P Magazine* 19(2). ⚠ DOI unconfirmed. Relevant to: RQ3.
- Spring, J. M., et al. (2019). SSVC. SEI/CMU. Relevant to: a possible fourth condition in E3.
- Allodi, L., et al. (2020). Measuring the accuracy of software vulnerability assessments. *EMSE* 25(2). DOI 10.1007/s10664-019-09797-4. **Design template for E3.** (The 2018 version appeared at WEIS, not CCS.)
- Wunder, J., et al. (2024). Shedding Light on CVSS Scoring Inconsistencies. *IEEE S&P 2024*. DOI 10.1109/SP54263.2024.00058. 68% of raters gave inconsistent severities. Relevant to: E3 baseline.
- Koscinski, V., et al. (2025). Conflicting Scores, Confusing Signals. arXiv:2508.13644. Relevant to: RQ3.

## SMEs and adoption
- Rombaldo Junior, C., Becker, I., & Johnson, S. D. (2025). Unaware, Unfunded, Untrained and Unsupported: A Systematic Review of SME Cybersecurity. arXiv:2309.17186. Relevant to: RQ5.
- Huaman, N., et al. (2021). Large-Scale Interview Study on Information Security in SMEs. *USENIX Security '21*. Relevant to: RQ5, E5.
- Ryan, I., Stol, K.-J., & Roedig, U. (2023). Secure Coding Practice in Small Organisations. *EnCyCriS 2023*. DOI 10.1109/EnCyCriS59249.2023.00010. Relevant to: RQ2, RQ5.
- Asadi, R., et al. (2025). No Silver Bullet: Secure Software Development for Danish SMEs. *CHI 2025*. DOI 10.1145/3706598.3713931. Relevant to: RQ4, RQ5.
- Assal, H., & Chiasson, S. (2019). *CHI 2019*. DOI 10.1145/3290605.3300519. Witschey, J., et al. (2015). *ESEC/FSE '15*. DOI 10.1145/2786805.2786816. Johnson, B., et al. (2013). *ICSE 2013*. Relevant to: RQ5 tool adoption.

## Reporting and tabletop exercises
- Li, F., & Paxson, V. (2017). *CCS '17*. DOI 10.1145/3133956.3134072. Arora, A., et al. (2010). *ISR* 21(1). DOI 10.1287/isre.1080.0226. Decan, A., Mens, T., & Constantinou, E. (2018). *MSR 2018*. DOI 10.1145/3196398.3196401. Relevant to: timeliness baselines.
- NIST SP 800-84 (2006). DOI 10.6028/NIST.SP.800-84. Vykopal, J., et al. (2024). *ITiCSE '24*. DOI 10.1145/3649217.3653642. Angafor, G. N., et al. (2023). *ICS* 31(4). DOI 10.1108/ICS-05-2022-0085. Relevant to: E5 method.

## Methods
Hevner, A. R., et al. (2004), *MISQ* 28(1) · Peffers, K., et al. (2007), *JMIS* 24(3) · Wieringa, R. J. (2014), Springer · Runeson, P., & Höst, M. (2009), *EMSE* 14 · Brooke, J. (1996), SUS · Bangor, A., Kortum, P., & Miller, J. (2009), *JUS* 4(3) · Cohen, J. (1968), weighted κ · Hayes, A. F., & Krippendorff, K. (2007), *CMM* 1(1) · Koo, T. K., & Li, M. Y. (2016), *J. Chiropr. Med.* 15(2) · Venkatesh, V., et al. (2003), UTAUT, *MISQ* 27(3). Shrout & Fleiss (1979) and Krippendorff (2011) are the reference values used in `tests/test_agreement.py`.

## Gaps per RQ (one-line summaries for the introduction)
- **RQ1:** Mappings exist [Ruohonen 2025, 2026; Koutidis 2026], but none is verifiable or reproducible, and agreement between mappers is modest.
- **RQ2:** No effort measurements of CRA preparation exist for SMEs. Continuous compliance has only been shown at hyperscaler scale [Kellogg 2020].
- **RQ3:** Matrix flaws [Cox] and CVSS inconsistency [Wunder 2024; Allodi 2020] are documented, but no study compares the agreement of qualitative and FAIR-style assessment on the same product-risk scenarios.
- **RQ4:** Tools disagree [Imtiaz 2021; O'Donoghue 2024; Zhou 2025]. No metrics exist for evidence freshness or false assurance relative to a compliance claim.
- **RQ5:** SME barriers are well documented, but no adoption study of CRA tooling exists.
