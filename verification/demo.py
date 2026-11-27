import io,os,pathlib,sys,unittest
import contract_checks_r2 as contract_checks
class Result(unittest.TextTestResult):
 def addSuccess(self,test):
  super().addSuccess(test);print('PASS '+test._testMethodName.removeprefix('test_'),flush=True)
 def addFailure(self,test,err):
  super().addFailure(test,err);print('FAIL '+test._testMethodName.removeprefix('test_'),flush=True)
 def addError(self,test,err):
  super().addError(test,err);print('ERROR '+test._testMethodName.removeprefix('test_'),flush=True)
print('Local checks against the frozen source',flush=True)
print('Generated fixtures only; no remote service',flush=True)
out=io.StringIO()
suite=unittest.defaultTestLoader.loadTestsFromModule(contract_checks)
r=unittest.TextTestRunner(stream=out,verbosity=2,resultclass=Result).run(suite)
p=pathlib.Path(os.environ['DEMO_WORK_ROOT']);p.mkdir(parents=True,exist_ok=True)
(p/'actual-unittest-output.log').write_text(out.getvalue(),encoding='utf8')
print(f'Completed {r.testsRun}: {r.testsRun-len(r.failures)-len(r.errors)} passed, {len(r.failures)} failed, {len(r.errors)} errors',flush=True)
sys.exit(0 if r.wasSuccessful() else 1)
