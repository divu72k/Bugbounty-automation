import asyncio
import json

async def run(cmd):
	proc=await asyncio.create_subprocess_shell(
		cmd,
		stdout=asyncio.subprocess.PIPE,
		stderr=asyncio.subprocess.PIPE)

	stdout,stderr=await proc.communicate()
	if stdout:
		return stdout.decode().strip().splitlines()
	if stderr:
		print(f"[ERROR] {stderr.decode().strip()}")
	return []

async def main(target_urls):
	hak=f" cat {target_urls} | hakrawler"
	wayback=f" cat {target_urls} | waybackurls"
	
	hak_tsk= asyncio.create_task(run(hak))
	wayback_tsk= asyncio.create_task(run(wayback))
	
	hak_opt, wayback_opt= await asyncio.gather(hak_tsk, wayback_tsk)
	
	html_hak= [i for i in hak_opt if ".html" in i]
	html_wayback=[i for i in wayback_opt if ".html" in i]
	all_res=html_hak + html_wayback
	common=set(all_res)
	
	opt= "subs.json"
	with open(opt, 'w') as f:
		json.dump(list(common),f,indent=4)
	print("crawled successfully")


if __name__=="__main__":
	target=input("Enter the file with target URLs: ")
	asyncio.run(main(target))
