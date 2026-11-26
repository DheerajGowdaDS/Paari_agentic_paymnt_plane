"""The acceptance gate must never greenlight missing/xfail regulatory cases."""
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree
from scripts.regulatory_mvp_gate_v352 import examine_junit


def _write(tmp_path, skip=None, missing=None):
    root=Element('testsuite')
    for n in range(1,15):
        if n == missing:continue
        el=SubElement(root,'testcase',name=f'test_c{n:02d}_scenario',classname='tests.test_e2e_mvp_acceptance')
        if n == skip:SubElement(el,'skipped',message='xfail: not implemented')
    path=Path(tmp_path)/'result.xml';ElementTree(root).write(path)
    return path


def test_all_required_cases_pass_when_all_present(tmp_path):
    assert examine_junit(_write(tmp_path))['status']=='PASS'


def test_missing_case_must_fail_even_with_pytest_exit_zero(tmp_path):
    r=examine_junit(_write(tmp_path,missing=6))
    assert r['status']=='FAIL' and r['cases']['C06'] is False


def test_xfail_must_fail_even_with_pytest_exit_zero(tmp_path):
    r=examine_junit(_write(tmp_path,skip=6))
    assert r['status']=='FAIL' and r['cases']['C06'] is False
