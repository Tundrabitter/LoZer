from faker import Faker
import random

fake = Faker()

def generate_log_entry():
    ip = fake.ipv4()
    date = fake.date_time_this_year().strftime('%d/%b/%Y:%H:%M:%S +0000')
    method = random.choice(["GET", "POST"])
    path = random.choice(["/", "/login", "/api/data", "/admin"])
    status = random.choice([200, 200, 200, 404, 401, 403, 500])  # More 200s to simulate normal traffic
    return f'{ip} - - [{date}] "{method} {path} HTTP/1.1" {status} {fake.random_int(200, 5000)}\n'

with open('/Users/polzovael/Desktop/Projects/sample_logs/access.log', 'w') as f:
    for i in range(1000):  # Generate 1000 lines
        f.write(generate_log_entry())