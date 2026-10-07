"""Cascades use normal upstream dispatch and all unified protocol surfaces."""

import json
from unittest.mock import patch

import requests

from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {'Authorization': 'Bearer admin-test-key'}


class CascadeApiTests(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        from services.cascade_service import CascadeService
        self.config = {'name': 'cascade:api', 'tiers': [{'model': 'opencode:cheap'}, {'model': 'opencode:strong'}], 'checks': ['complete']}
        CascadeService.save_route(self.config, self.app.config['API_BASE_URLS'])

    def _upstream(self, text='4', finish='stop'):
        response = self._chat_response(text)
        body = json.loads(response.content)
        body['choices'][0]['finish_reason'] = finish
        body['usage'] = {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}
        response._content = json.dumps(body).encode()
        response._content_consumed = True
        return response

    def test_models_listing_and_cors(self):
        response = self.client.get('/v1/models', headers=ADMIN)
        entry = next(model for model in response.get_json()['data'] if model['id'] == 'cascade:api')
        self.assertEqual(entry['owned_by'], 'multillm-cascade')
        response = self.client.options('/v1/chat/completions', headers={'Origin': 'https://synthetic.invalid'})
        self.assertIn('X-MultiLLM-Cascade', response.headers['Access-Control-Expose-Headers'])

    def test_three_protocols_and_optimizer_use_make_request(self):
        requests_by_path = {
            '/v1/chat/completions': {'messages': [{'role': 'user', 'content': 'two plus two'}]},
            '/optimize/v1/chat/completions': {'messages': [{'role': 'user', 'content': 'two plus two'}]},
            '/v1/responses': {'input': 'two plus two', 'store': False},
            '/v1/messages': {'messages': [{'role': 'user', 'content': 'two plus two'}], 'max_tokens': 30},
        }
        for path, body in requests_by_path.items():
            with self.subTest(path=path), patch('app.ProxyService.make_request', return_value=self._upstream()) as upstream:
                response = self.client.post(path, headers=ADMIN, json={'model': 'cascade:api', **body})
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                self.assertEqual(upstream.call_count, 1)
                sent = json.loads(upstream.call_args.kwargs['data'])
                self.assertEqual(sent['model'], 'cheap')
                self.assertFalse(sent['stream'])
                self.assertIn('tier=1/2; model=opencode:cheap', response.headers['X-MultiLLM-Cascade'])

    def test_streaming_replay_on_all_protocols(self):
        for path, body in {
            '/v1/chat/completions': {'messages': [{'role': 'user', 'content': 'hello'}]},
            '/v1/responses': {'input': 'hello', 'store': False},
            '/v1/messages': {'messages': [{'role': 'user', 'content': 'hello'}], 'max_tokens': 30},
        }.items():
            with self.subTest(path=path), patch('app.ProxyService.make_request', return_value=self._upstream()):
                response = self.client.post(path, headers=ADMIN, json={'model': 'cascade:api', 'stream': True, **body})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, 'text/event-stream')
                raw = response.get_data(as_text=True)
                self.assertIn('4', raw)
                terminal = {'/v1/chat/completions': '[DONE]', '/v1/responses': 'response.completed', '/v1/messages': 'message_stop'}[path]
                self.assertIn(terminal, raw)
                response.close()

    def test_final_stream_setting_passes_to_upstream(self):
        streamed = requests.Response()
        streamed.status_code = 200
        streamed._content = b'data: {"id":"synthetic","choices":[{"index":0,"delta":{"content":"final"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        streamed._content_consumed = True
        streamed.headers['Content-Type'] = 'text/event-stream'
        with patch('app.ProxyService.make_request', side_effect=[self._upstream('', 'length'), streamed]) as upstream:
            response = self.client.post('/v1/chat/completions', headers=ADMIN, json={'model': 'cascade:api', 'messages': [{'role': 'user', 'content': 'hello'}], 'stream': True})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(json.loads(upstream.call_args.kwargs['data'])['stream'])
            self.assertIn('final', response.get_data(as_text=True))
            self.assertIn('tier=2/2', response.headers['X-MultiLLM-Cascade'])
            response.close()

    def test_server_state_features_rejected_before_upstream(self):
        for field in ({'previous_response_id': 'synthetic-response'}, {'background': True}, {'conversation': 'synthetic-conversation'}, {'prompt': {'id': 'synthetic-prompt'}}):
            with patch('app.ProxyService.make_request') as upstream:
                response = self.client.post('/v1/responses', headers=ADMIN, json={'model': 'cascade:api', 'input': 'hello', **field})
                self.assertEqual(response.status_code, 400)
                upstream.assert_not_called()

    def test_dashboard_save_validation_and_authorization(self):
        response = self.client.get('/admin/cascades')
        self.assertNotEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            session['authenticated'] = True
            session['user'] = {'username': 'admin', 'is_admin': True, 'api_key_prefix': 'mllm_admin-te', 'scopes': ['admin']}
        response = self.client.put('/admin/cascades', json={**self.config, 'name': 'cascade:edited'})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn('cascade:edited', [item['name'] for item in response.get_json()['cascades']])
        response = self.client.put('/admin/cascades', json={**self.config, 'tiers': []})
        self.assertEqual(response.status_code, 400)
        page = self.client.get('/')
        self.assertIn('cascade-config', page.get_data(as_text=True))

    def test_nested_auto_model_allowlist(self):
        from services.auto_route_service import AutoRouteService
        from services.cascade_service import CascadeService
        AutoRouteService.save_route('auto:synthetic', ['opencode:forbidden', 'opencode:permitted'], self.app.config['API_BASE_URLS'])
        CascadeService.save_route({**self.config, 'tiers': [{'model': 'auto:synthetic'}, {'model': 'opencode:strong'}]}, self.app.config['API_BASE_URLS'])
        from services import key_controls
        original = key_controls.model_allowed
        with patch.object(key_controls, 'model_allowed', side_effect=lambda user, model: model != 'opencode:forbidden' and original(user, model)), patch('app.ProxyService.make_request', return_value=self._upstream()) as upstream:
            response = self.client.post('/v1/chat/completions', headers=ADMIN, json={'model': 'cascade:api', 'messages': [{'role': 'user', 'content': 'hello'}]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(upstream.call_args.kwargs['data'])['model'], 'permitted')
        self.assertIn('model=opencode:permitted', response.headers['X-MultiLLM-Cascade'])
