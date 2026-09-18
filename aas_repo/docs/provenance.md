# Provenance and file mapping

The uploaded archive mixed executable code, presentation material, interview notes, and extracted modules. This
repository separates those concerns while preserving the final competition artifact.

| Uploaded file | Repository location / treatment |
| --- | --- |
| `CD.py` | `notebooks/final_submission.py`; its embedded `attack_code` is extracted byte-for-byte as `submission/attack.py`. |
| `SECRET_MARKER.py` | `baselines/secret_marker.py`; retained as an earlier experimental baseline. |
| `extracted_modules/*.py` | `experiments/extracted_modules/*.py`; historical profile builders preserved unchanged. |
| `CD.py_深度解读与私榜风险评估.md` | Condensed into `docs/risk-analysis.md` and `docs/known-issues.md`. |
| `面试讲解稿_AAS比赛.md` | Used as source material for `README*` and `docs/algorithm.md`; personal interview framing is not copied into the public repository. |
| `OpenAI-AAS竞赛算法讲解.pdf` | Used to verify architecture, scoring-flow, and submission-lifecycle descriptions; binary slide asset omitted to keep the code repository focused. |
| `OpenAI-AAS竞赛简历.docx` | Used to cross-check the project summary; resume-formatted binary is intentionally omitted from the public code repository. |
| slide screenshots / `.page` sources | Omitted as redundant presentation build artifacts. |

No competition result is recomputed by this reorganization. The final executable artifact remains the extracted
submission code from the provided archive.
