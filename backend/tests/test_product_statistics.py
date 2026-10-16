import time
from fastapi.testclient import TestClient
from aegisav.api import create_app


class Scanner:
    def scan(self, data):
        if data == b'bad':
            raise ValueError('inert invalid fixture')
        return {'verdict':'undetermined','sha256':'a'*64,'cached':False,
                'engines':{'sha256':{'status':'no_match','elapsed_ms':1},
                           'lightgbm':{'status':'not_applicable','elapsed_ms':2}}}


def test_statistics_preserve_failure_missing_evidence_and_have_no_fake_accuracy(tmp_path):
    with TestClient(create_app(Scanner(),db_path=tmp_path/'tasks.sqlite3')) as client:
        job = client.post('/v1/tasks',json={'files':[
            {'name':'a','content_base64':'YQ=='},{'name':'bad','content_base64':'YmFk'}]}).json()
        for _ in range(100):
            if client.get('/v1/tasks/'+job['id']).json()['status']=='completed_with_errors':
                break
            time.sleep(.01)
        response = client.get('/v1/statistics')
        assert response.status_code==200
        stats = response.json()
        assert stats['task_count']==1 and stats['file_count']==2
        assert stats['file_statuses']=={'completed':1,'error':1}
        assert stats['accuracy']['available'] is False
        assert stats['recent']['reports']==1 and stats['recent']['distinct_report_sha256']==1
        assert stats['recent']['engines']['sha256']['statuses']=={'no_match':1}
        assert stats['recent']['engines']['lightgbm']['abstentions']==1
        assert stats['recent']['engines']['yara_x']['statuses']=={'missing':1}
        assert client.get('/v1/tasks?state=terminal').json()['tasks'][0]['id']==job['id']
        assert client.get('/v1/tasks?state=active').json()['tasks']==[]
        assert client.get('/v1/tasks?state=wrong').status_code==422


def test_model_inventory_exposes_general_fallback_and_per_model_frozen_thresholds():
    scanner = Scanner()
    class Model:
        profile='win64_low_fpr'
        artifact_version='frozen-registry'
        manifest={'models':{'general':{'version':'general-v1','scope':['win32','win64','dot_net'],'threshold':.5},
                            'win64':{'version':'win64-v1','scope':['win64'],'threshold':.99}}}
        def probe(self):
            return True
    scanner.ml_engine=Model()
    with TestClient(create_app(scanner)) as client:
        model=client.get('/v1/engines').json()['ml']
        assert model['routing']=={'win32':'general','dot_net':'general','win64':'win64','unsupported':'abstain'}
        assert model['models']['general']['threshold']==.5
        assert model['models']['win64']['threshold']==.99
        assert model['models']['general']['version']=='general-v1'
