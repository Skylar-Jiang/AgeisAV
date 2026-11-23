from vm.diagnose_static_case import models_for_scope
import pytest

def test_win32_diagnosis_never_scores_inapplicable_win64_model():
 models={'general':{'file':'g'},'win64':{'file':'w'}}
 assert models_for_scope(models,'win32')=={'general':models['general']}
 assert models_for_scope(models,'win64')==models

def test_case_diagnosis_refuses_other_architecture_or_missing_general():
 with pytest.raises(ValueError):models_for_scope({'general':{}},'unsupported')
 with pytest.raises(ValueError):models_for_scope({'win64':{}},'win32')
