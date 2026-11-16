import importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('release',pathlib.Path(__file__).with_name('owner-dns-release-20261116.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RecoveryTests(unittest.TestCase):
    def test_committed_release_is_never_rolled_back_by_stale_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'COMMITTED').write_text('done')
            with patch.object(m,'ROOT',root),patch.object(m,'run') as run:
                m.rollback();run.assert_not_called()

    def test_untouched_live_bot_is_not_stopped_when_canary_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'original-bot.json').write_text(json.dumps({'Id':'original'}))
            names={m.BOT,m.OLD_BOT}
            with patch.object(m,'ROOT',root),patch.object(m,'exists',side_effect=lambda name:name in names),patch.object(m,'inspect',return_value={'Id':'original'}),patch.object(m,'run') as run:
                m.rollback()
                self.assertEqual(run.call_args_list[0].args[0],['docker','rm','-f',m.OLD_BOT])
                self.assertEqual(run.call_count,1)

    def test_failed_promoted_gateway_restores_preserved_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'original-private.json').write_text(json.dumps({'Id':'old'}))
            names={m.PRIVATE,m.OLD_PRIVATE,m.CANARY}
            with patch.object(m,'ROOT',root),patch.object(m,'exists',side_effect=lambda name:name in names),patch.object(m,'inspect',return_value={'Id':'new'}),patch.object(m,'run') as run:
                m.rollback()
                calls=[c.args[0] for c in run.call_args_list]
                self.assertEqual(calls[:3],[['docker','rm','-f',m.PRIVATE],['docker','rename',m.OLD_PRIVATE,m.PRIVATE],['docker','start',m.PRIVATE]])
                self.assertEqual(calls[-1],['docker','rm','-f',m.CANARY])

    def test_credentials_are_in_private_env_file_and_original_limits_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            original={'Config':{'Env':['PASSWORD=private-value'],'User':'1001:1001','Entrypoint':['node'],'Cmd':['server.ts']},'HostConfig':{'PidsLimit':96,'Memory':268435456,'NanoCpus':500000000},'Mounts':[],'Image':'sha256:test'}
            with patch.object(m,'ROOT',root),patch.object(m,'run') as run:
                m.create(original,'canary',start=False)
                args=run.call_args.args[0]
                self.assertNotIn('private-value',' '.join(args));self.assertIn('--read-only',args)
                self.assertEqual(args[args.index('--user')+1],'1001:1001')
                env=root/'canary.env';self.assertEqual(env.stat().st_mode&0o777,0o600)
                self.assertEqual(env.read_text(),'PASSWORD=private-value\n')

    def test_missing_image_recovery_preserves_original_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            original={'Config':{'Env':['PATH=/usr/local/bin:/usr/bin'],'User':'1000:1000','WorkingDir':'/srv/mnebyvpn','Entrypoint':['node'],'Cmd':['server.ts']},'HostConfig':{'PidsLimit':96,'Memory':268435456,'NanoCpus':350000000},'Mounts':[],'Image':'missing-original'}
            with patch.object(m,'ROOT',root),patch.object(m,'run') as run:
                m.create(original,'backup','recovery-image',start=False)
                args=run.call_args.args[0]
                self.assertEqual(args[args.index('--workdir')+1],'/srv/mnebyvpn')
                self.assertIn('recovery-image',args);self.assertNotIn('missing-original',args)

    def test_missing_image_backup_refuses_unpreserved_volume_data(self):
        original={'Image':'missing','Mounts':[{'Source':'/data'}],'HostConfig':{'ReadonlyRootfs':True}}
        with patch.object(m,'run',side_effect=RuntimeError('missing')):
            with self.assertRaisesRegex(RuntimeError,'immutable bot without mounts'):
                m.bot_backup_image(original)

if __name__=='__main__':unittest.main()
