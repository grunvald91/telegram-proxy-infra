import {chromium} from 'playwright';
const browser=await chromium.launch({headless:true,args:['--no-sandbox'],...(
process.env.VISUAL_CHROME_PATH?{executablePath:process.env.VISUAL_CHROME_PATH}:{})});
const page=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
const errors=[],api=[];
page.on('pageerror',e=>errors.push(String(e.message).slice(0,220)));
page.on('response',r=>{if(new URL(r.url()).pathname==='/api/plans')api.push(r.status());});
const out={};
try{
  const navigation=await page.goto('https://mnebyvpn.site/#plans',{waitUntil:'domcontentloaded',timeout:25000});
  out.document_http=navigation?.status()??0;
  await page.waitForTimeout(5500);
  out.site_catalog_api_status=api.join(',');
  out.site_browser_errors=errors;
  out.state=await page.evaluate(()=>({journeyActive:document.body.classList.contains('journey-active'),
    view:document.body.dataset.journeyView,
    buyDisabled:document.getElementById('journey-buy')?.disabled,
    buyText:document.getElementById('journey-buy')?.textContent?.slice(0,110),
    summary:document.getElementById('journey-summary')?.textContent?.slice(0,110),
    emailFormHidden:document.getElementById('email-auth-panel')?.classList.contains('hidden'),
    plansFetched:performance.getEntriesByType('resource').some(x=>x.name.includes('/api/plans')),
    frame:document.getElementById('journey-front-frame')?.getAttribute('src'),
    frontReady:document.getElementById('journey-front-frame')?.contentDocument?.readyState,
    jsResources:performance.getEntriesByType('resource').filter(x=>/\/(app|journey)\.js(?:$|\?)/.test(x.name)).map(x=>x.name),
  }));
  const iframe=page.frameLocator('#journey-front-frame');
  out.iframe=await iframe.locator('.cta').evaluate(el=>({
    disabled:el.disabled,text:el.textContent?.slice(0,100),
    days:[...document.querySelectorAll('.plans-vpn .plan')].map(x=>({
      days:x.dataset.d,disabled:x.disabled,price:x.querySelector('strong')?.textContent
    }))
  })).catch(e=>({error:String(e.message).slice(0,160)}));
  await page.locator('.journey-header-account').click({timeout:6000});
  await page.waitForTimeout(800);
  out.account=await page.evaluate(()=>{
    const el=document.getElementById('email-auth-panel');
    const input=document.getElementById('email-input');
    return {view:document.body.dataset.journeyView,hash:location.hash,
      loginPromptVisible:!!document.getElementById('login-prompt')&&getComputedStyle(document.getElementById('login-prompt')).display!=='none',
      formHidden:el?.classList.contains('hidden'),
      formDisplay:el?getComputedStyle(el).display:null,
      inputVisible:!!input&&input.getBoundingClientRect().width>0,
      loginPromptText:document.getElementById('login-prompt-copy')?.textContent?.slice(0,140)
    };
  });
  await page.goto('https://mnebyvpn.site/#account',{waitUntil:'domcontentloaded',timeout:25000});
  await page.waitForTimeout(2200);
  out.directAccount=await page.evaluate(()=>({
    view:document.body.dataset.journeyView,
    formHidden:document.getElementById('email-auth-panel')?.classList.contains('hidden'),
    inputVisible:document.getElementById('email-input')?.getBoundingClientRect().width>0,
  }));
  console.log('READONLY_LIVE_WEB_AUDIT='+JSON.stringify(out));
}finally{await browser.close();}
