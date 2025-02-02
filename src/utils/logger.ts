import core from '@actions/core'

const log=(msg:unknown)=>{
    core.notice(msg as string)
}
const warn=(msg:unknown)=>{
    core.warning(msg as string)
}
const error=(msg:unknown)=>{
    core.error(msg as string)


}
export const logger ={
    log:log,
    info:log,
    warn, error

}
