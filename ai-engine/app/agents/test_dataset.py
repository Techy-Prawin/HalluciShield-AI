"""
Fixed benchmark dataset for HalluciShield research experiments.
Dataset version: v1.0
45 test cases across 9 vulnerability categories (5 each).
"""
from typing import List
from app.agents.models import TestCase, VulnerabilityTestCategory

DATASET_VERSION = "v1.0"

from app.agents.test_dataset_part1 import SQL_TEST_CASES, XSS_TEST_CASES, CMD_TEST_CASES, PATH_TEST_CASES, SECRET_TEST_CASES
from app.agents.test_dataset_part2 import JWT_TEST_CASES, AUTH_TEST_CASES, HAPI_TEST_CASES, HPKG_TEST_CASES

ALL_TEST_CASES: list[TestCase] = SQL_TEST_CASES + XSS_TEST_CASES + CMD_TEST_CASES + PATH_TEST_CASES + SECRET_TEST_CASES + JWT_TEST_CASES + AUTH_TEST_CASES + HAPI_TEST_CASES + HPKG_TEST_CASES

ALL_TEST_CASES_BY_ID: dict[str, TestCase] = {tc.test_id: tc for tc in ALL_TEST_CASES}
ALL_TEST_CASES_BY_CATEGORY: dict[str, list[TestCase]] = {}
for tc in ALL_TEST_CASES:
    ALL_TEST_CASES_BY_CATEGORY.setdefault(tc.vuln_category.value, []).append(tc)
