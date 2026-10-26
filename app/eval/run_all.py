"""
Run the full eval suite and print a combined report.

Run: python -m app.eval.run_all [--structural-only]
"""
import argparse
from app.eval.retrieval_eval import evaluate_retrieval, print_report as print_retrieval_report
from app.eval.remediation_eval import run_eval as run_remediation_eval, print_report as print_remediation_report


def main(structural_only: bool = False):
    print("=" * 60)
    print("RETRIEVAL EVAL")
    print("=" * 60)
    retrieval_report = evaluate_retrieval(k=3)
    print_retrieval_report(retrieval_report)

    print()
    print("=" * 60)
    print("REMEDIATION EVAL")
    print("=" * 60)
    remediation_report = run_remediation_eval(limit=10, structural_only=structural_only)
    print_remediation_report(remediation_report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--structural-only", action="store_true")
    args = parser.parse_args()
    main(structural_only=args.structural_only)
