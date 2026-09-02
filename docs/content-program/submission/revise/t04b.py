"""T-04, second pass — give the paper the reference list it never had.

§8 cited sixteen works inline (author, venue, arXiv id) with no bibliography, which is a reason a
preprint server bounces a submission on its own. Every entry below was resolved against a primary
source on 2026-09-02: the arXiv API by identifier for the seven arXiv works, and the ACL Anthology,
CVF Open Access or ECVA page for the rest. Nothing was cited from memory.

One in-text correction came out of the resolution: the ECCV 2024 drift-compensation paper is
Gomez-Villa et al. -- Goswami is the second author, not the first.
"""
from _lib import main

REFERENCES = """## References

[Twist et al. 2026] L. Twist et al. *Reasoning-Trace Collapse: Evaluating the Loss of Explicit
Reasoning During Fine-Tuning.* arXiv:2605.21127, 2026.

[Ghosh et al. 2025] S. Ghosh et al. *AEGIS2.0: A Diverse AI Safety Dataset and Risks Taxonomy for
Alignment of LLM Guardrails.* NAACL 2025.

[Fang et al. 2021] C. Fang, H. He, Q. Long and W. J. Su. *Exploring Deep Neural Networks via
Layer-Peeled Model: Minority Collapse in Imbalanced Training.* PNAS 118(43), 2021.

[Choudhary et al. 2026] A. Choudhary et al. *Asymmetric Collapse in Model Merging: When Refusal
Overwrites Recognition.* COLM 2026; arXiv:2607.27240.

[Tang et al. 2020] H. Tang, J. Liu, M. Zhao and X. Gong. *Progressive Layered Extraction (PLE): A
Novel Multi-Task Learning (MTL) Model for Personalized Recommendations.* RecSys 2020.

[Yu et al. 2020] L. Yu et al. *Semantic Drift Compensation for Class-Incremental Learning.* CVPR 2020.

[Gomez-Villa et al. 2024] A. Gomez-Villa, D. Goswami, K. Wang, A. D. Bagdanov, B. Twardowski and
J. van de Weijer. *Exemplar-Free Continual Representation Learning via Learnable Drift
Compensation.* ECCV 2024.

[Xu et al. 2026] R. Xu et al. *Mask the Target: A Plug-and-Play Regularizer Against LoRA Forgetting.*
arXiv:2605.29498, 2026.

[Zhang et al. 2025] J. Zhang et al. *LoRI: Reducing Cross-Task Interference in Multi-Task Low-Rank
Adaptation.* arXiv:2504.07448, 2025.

[Yang et al. 2026] Z. Yang et al. *Disentangling Task Conflicts in Multi-Task LoRA via Orthogonal
Gradient Projection.* arXiv:2601.09684, 2026.

[Kokkinos 2017] I. Kokkinos. *UberNet: Training a Universal Convolutional Neural Network for Low-,
Mid-, and High-Level Vision Using Diverse Datasets and Limited Memory.* CVPR 2017.

[Li et al. 2022] W.-H. Li, X. Liu and H. Bilen. *Learning Multiple Dense Prediction Tasks from
Partially Annotated Data.* CVPR 2022.

[Lin et al. 2024] Z. Lin et al. *Rho-1: Not All Tokens Are What You Need.* arXiv:2404.07965, 2024.

[Huerta-Enochian and Ko 2024] M. Huerta-Enochian and S. Y. Ko. *Instruction Fine-Tuning: Does
Prompt Loss Matter?* EMNLP 2024.

[Betley et al. 2025] J. Betley et al. *Emergent Misalignment: Narrow Finetuning Can Produce Broadly
Misaligned LLMs.* arXiv:2502.17424, 2025.

[Zhang et al. 2026] Y. Zhang et al. *Where vs What: Decomposing Structural and Content Failures in
LLM-Generated Structured Outputs.* arXiv:2608.25358, 2026.

---

## Production notes (strip before submission)"""

EDITS = [
    ("compensation exists (Yu\n"
     "et al., CVPR 2020; Goswami et al., ECCV 2024).",
     "compensation exists (Yu\n"
     "et al., CVPR 2020; Gomez-Villa et al., ECCV 2024)."),

    ("could not find either sentence written down.\n"
     "\n"
     "---\n"
     "\n"
     "## Production notes (strip before submission)",
     "could not find either sentence written down.\n"
     "\n"
     "---\n"
     "\n" + REFERENCES),
]

main("T-04-masking-does-not-isolate.md", EDITS)
