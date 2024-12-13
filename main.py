import subprocess

def run_offline_phase():
    subprocess.run(["python", "offline_phase.py"])

def run_online_phase():
    subprocess.run(["python", "online_phase.py"])

if __name__ == "__main__":
    run_offline_phase()
    run_online_phase()
