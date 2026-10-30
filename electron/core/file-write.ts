import {constants} from 'node:fs'
import {copyFile,link} from 'node:fs/promises'
/** Publish without replacing any existing destination. The exclusive-copy fallback
 * supports filesystems without hard links; unlike link, that fallback is not atomic. */
export async function publishNewFile(temp:string,path:string,tryLink:typeof link=link){
 try{await tryLink(temp,path)}catch(error){
  if(!['ENOTSUP','EOPNOTSUPP','EPERM','ENOSYS','EXDEV'].includes((error as NodeJS.ErrnoException).code??''))throw error
  await copyFile(temp,path,constants.COPYFILE_EXCL)
 }
}
