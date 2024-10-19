import http from 'k6/http';

const baseUrl = 'http://localhost:8000';

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      stages: [
        { target: 90000, duration: '15m' },
      ],
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
  },
};


export default function() {
  http.request('POST', `${baseUrl}/user-register`, {'username': 'admin', 'name': 'admin', 'birthdate': '2024-10-10T02:59:10.843897', 'password': 'superSecretAdminPassword123'})
}