import createLogger from 'debug'
import defer from 'golike-defer'
import execa from 'execa'
import fs from 'fs-extra'
import map from 'lodash/map'
import { tap } from 'promise-toolbox'
import {
  includes,
  forOwn,
  isArray,
  find,
  remove,
  filter
} from 'lodash'

import {
  asyncMap,
  parseXml
} from '../utils'

const debug = createLogger('xo:xosan')

const SSH_KEY_FILE = 'id_rsa_xosan'
const NETWORK_PREFIX = '172.31.100.'

const XOSAN_VM_SYSTEM_DISK_SIZE = 10 * 1024 * 1024 * 1024
const XOSAN_DATA_DISK_USEAGE_RATIO = 0.99
const XOSAN_MAX_DISK_SIZE = 2093050 * 1024 * 1024 // a bit under 2To

const CURRENTLY_CREATING_SRS = {}

function _getIPToVMDict (xapi, sr) {
  const dict = {}
  dict.vmForBrick = brick => {
    // IPV6
    return dict[brick.split(':')[0]]
  }
  const data = xapi.xo.getData(sr, 'xosan_config')
  if (data && data.nodes) {
    const nodes = data.nodes
    nodes.forEach(conf => {
      try {
        dict[conf.vm.ip] = xapi.getObject(conf.vm.id)
      } catch (e) {
        // pass
      }
    })
  }
  return dict
}

function _getGlusterEndpoint (xapi, sr) {
  const data = xapi.xo.getData(sr, 'xosan_config')
  if (!data || !data.nodes) {
    return null
  }
  const oneHostAndVm = data.nodes[0]
  return { xapi, host: xapi.getObject(oneHostAndVm.host), addresses: map(data.nodes, node => node.vm.ip) }
}

export async function getVolumeInfo ({ sr }) {
  const xapi = this.getXapi(sr)
  const glusterEndpoint = _getGlusterEndpoint(xapi, sr)
  const giantIPtoVMDict = _getIPToVMDict(xapi, sr)
  const volumeCommands = ['info xosan', 'status xosan', 'heal xosan info']
  function parseIfOk (glusterResult) {
    if (glusterResult['exit'] === 0) {
      const parsed = parseXml(glusterResult['stdout'])
      if (parsed['cliOutput']['opRet'] === '0') {
        return parsed['cliOutput']
      }
    }
    return null
  }
  const [infoParsed, status, heal] = await asyncMap(volumeCommands, async cmd =>
    parseIfOk(await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume ' + cmd, true)))
  const brickDictByUuid = {}
  const brickDictByName = {}
  infoParsed['volInfo']['volumes']['volume']['bricks']['brick'].forEach(brick => {
    const name = brick['name']
    const vm = giantIPtoVMDict.vmForBrick(name)
    const brickValue = {
      info: brick,
      status: [],
      heal: {},
      splitbrain: {},
      uuid: brick['uuid'],
      vmId: vm ? vm.$id : null,
      vmLabel: vm ? vm.name_label : null
    }
    brickDictByUuid[brick.hostUuid] = brickValue
    brickDictByName[brick.name] = brickValue
  })
  if (heal !== null) {
    heal['healInfo']['bricks']['brick'].forEach(brick => {
      // disconnected bricks have their hostUuid filed set to '-' by the 'volume heal info' command, we grab them by name
      brickDictByName[brick.name]['heal'] = brick
      if (brick['file'] && !isArray(brick['file'])) {
        brick['file'] = [brick['file']]
      }
    })
  }
  if (status !== null) {
    status['volStatus']['volumes']['volume']['node'].forEach(node => {
      brickDictByUuid[node.peerid]['status'].push(node)
    })
  }
  const bricks = []
  forOwn(brickDictByUuid, value => {
    bricks.push(value)
  })
  infoParsed['volInfo']['volumes']['volume'].bricks = bricks
  infoParsed['volInfo']['volumes']['volume'].options = infoParsed['volInfo']['volumes']['volume'].options.option
  return infoParsed['volInfo']['volumes']['volume']
}

getVolumeInfo.description = 'info on gluster volume'
getVolumeInfo.permission = 'admin'

getVolumeInfo.params = {
  sr: {
    type: 'string'
  }
}
getVolumeInfo.resolve = {
  sr: ['sr', 'SR', 'administrate']
}
function floor2048 (value) {
  return 2048 * Math.floor(value / 2048)
}

async function copyVm (xapi, originalVm, sr) {
  return { sr, vm: await xapi.copyVm(originalVm, sr) }
}

async function prepareGlusterVm (xapi, vmAndParam, xosanNetwork, increaseDataDisk = true) {
  let vm = vmAndParam.vm
  // refresh the object so that sizes are correct
  const params = vmAndParam.params
  const ip = params.xenstore_data['vm-data/ip']
  const sr = xapi.getObject(params.sr.$id)
  await xapi._waitObjectState(sr.$id, sr => Boolean(sr.$PBDs))
  const host = sr.$PBDs[0].$host
  const firstVif = vm.$VIFs[0]
  if (xosanNetwork.$id !== firstVif.$network.$id) {
    try {
      await xapi.call('VIF.move', firstVif.$ref, xosanNetwork.$ref)
    } catch (error) {
      if (error.code === 'MESSAGE_METHOD_UNKNOWN') {
        // VIF.move has been introduced in xenserver 7.0
        await xapi.deleteVif(firstVif.$id)
        await xapi.createVif(vm.$id, xosanNetwork.$id, firstVif)
      }
    }
  }
  await xapi.editVm(vm, {
    name_label: params.name_label,
    name_description: params.name_description
  })
  await xapi.call('VM.set_xenstore_data', vm.$ref, params.xenstore_data)
  if (increaseDataDisk) {
    const dataDisk = vm.$VBDs.map(vbd => vbd.$VDI).find(vdi => vdi && vdi.name_label === 'xosan_data')
    const srFreeSpace = sr.physical_size - sr.physical_utilisation
    // we use a percentage because it looks like the VDI overhead is proportional
    const newSize = floor2048((srFreeSpace + dataDisk.virtual_size) * XOSAN_DATA_DISK_USEAGE_RATIO)
    await xapi._resizeVdi(dataDisk, Math.min(newSize, XOSAN_MAX_DISK_SIZE))
  }
  await xapi.startVm(vm)
  debug('waiting for boot of ', ip)
  // wait until we find the assigned IP in the networks, we are just checking the boot is complete
  const vmIsUp = vm => Boolean(vm.$guest_metrics && includes(vm.$guest_metrics.networks, ip))
  vm = await xapi._waitObjectState(vm.$id, vmIsUp)
  debug('booted ', ip)
  return { address: ip, host, vm }
}

async function callPlugin (xapi, host, command, params) {
  debug('calling plugin', host.address, command)
  return JSON.parse(await xapi.call('host.call_plugin', host.$ref, 'xosan.py', command, params))
}

async function remoteSsh (glusterEndpoint, cmd, ignoreError = false) {
  let result
  for (let address of glusterEndpoint.addresses) {
    result = await callPlugin(glusterEndpoint.xapi, glusterEndpoint.host, 'run_ssh', {
      destination: 'root@' + address,
      cmd: cmd
    })
    debug(result)
    // 255 seems to be ssh's own error codes.
    if (result.exit !== 255) {
      if (!ignoreError && result.exit !== 0) {
        throw new Error('ssh error: ' + JSON.stringify(result))
      }
      return result
    }
  }
  throw new Error(result ? 'ssh error: ' + JSON.stringify(result) : 'no suitable SSH host: ' + JSON.stringify(glusterEndpoint))
}

async function setPifIp (xapi, pif, address) {
  await xapi.call('PIF.reconfigure_ip', pif.$ref, 'Static', address, '255.255.255.0', NETWORK_PREFIX + '1', '')
}

const createNetworkAndInsertHosts = defer.onFailure(async function ($onFailure, xapi, pif, vlan) {
  let hostIpLastNumber = 1
  const xosanNetwork = await xapi.createNetwork({
    name: 'XOSAN network',
    description: 'XOSAN network',
    pifId: pif._xapiId,
    mtu: 9000,
    vlan: +vlan
  })
  $onFailure(() => xapi.deleteNetwork(xosanNetwork))
  await Promise.all(xosanNetwork.$PIFs.map(pif => setPifIp(xapi, pif, NETWORK_PREFIX + (hostIpLastNumber++))))

  return xosanNetwork
})
async function getOrCreateSshKey (xapi) {
  let sshKey = xapi.xo.getData(xapi.pool, 'xosan_ssh_key')

  if (!sshKey) {
    const readKeys = async () => {
      sshKey = {
        private: await fs.readFile(SSH_KEY_FILE, 'ascii'),
        public: await fs.readFile(SSH_KEY_FILE + '.pub', 'ascii')
      }
      xapi.xo.setData(xapi.pool, 'xosan_ssh_key', sshKey)
    }

    try {
      await readKeys()
    } catch (e) {
      await execa('ssh-keygen', ['-q', '-f', SSH_KEY_FILE, '-t', 'rsa', '-b', '4096', '-N', ''])
      await readKeys()
    }
  }

  return sshKey
}
async function configureGluster (redundancy, ipAndHosts, glusterEndpoint, glusterType, arbiter = null) {
  const configByType = {
    replica_arbiter: {
      creation: 'replica 3 arbiter 1',
      extra: []
    },
    replica: {
      creation: 'replica ' + redundancy + ' ',
      extra: ['gluster --mode=script --xml volume set xosan cluster.data-self-heal on']
    },
    disperse: {
      creation: 'disperse ' + ipAndHosts.length + ' redundancy ' + redundancy + ' ',
      extra: []
    }
  }
  let brickVms = arbiter ? ipAndHosts.concat(arbiter) : ipAndHosts
  for (let i = 1; i < brickVms.length; i++) {
    await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml peer probe ' + brickVms[i].address)
  }
  const creation = configByType[glusterType].creation
  const volumeCreation = 'gluster --mode=script --xml volume create xosan ' + creation +
    ' ' + brickVms.map(ipAndHost => _getBrickName(ipAndHost.address)).join(' ')
  debug('creating volume: ', volumeCreation)
  await remoteSsh(glusterEndpoint, volumeCreation)
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan network.remote-dio enable')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan cluster.eager-lock enable')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.io-cache off')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.read-ahead off')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.quick-read off')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.strict-write-ordering off')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan client.event-threads 8')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan server.event-threads 8')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.io-thread-count 64')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan performance.stat-prefetch on')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan features.shard on')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume set xosan features.shard-block-size 512MB')
  for (const confChunk of configByType[glusterType].extra) {
    await remoteSsh(glusterEndpoint, confChunk)
  }
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume start xosan')
}

export const createSR = defer.onFailure(async function ($onFailure, { template, pif, vlan, srs, glusterType, redundancy }) {
  if (!this.requestResource) {
    throw new Error('requestResource is not a function')
  }

  if (srs.length < 1) {
    return // TODO: throw an error
  }

  let vmIpLastNumber = 101
  const xapi = this.getXapi(srs[0])
  if (CURRENTLY_CREATING_SRS[xapi.pool.$id]) {
    throw new Error('createSR is already running for this pool')
  }

  CURRENTLY_CREATING_SRS[xapi.pool.$id] = true
  try {
    const xosanNetwork = await createNetworkAndInsertHosts(xapi, pif, vlan)
    $onFailure(() => xapi.deleteNetwork(xosanNetwork))
    const sshKey = await getOrCreateSshKey(xapi)
    const srsObjects = map(srs, srId => xapi.getObject(srId))
    await Promise.all(srsObjects.map(sr => callPlugin(xapi, sr.$PBDs[0].$host, 'receive_ssh_keys', {
      private_key: sshKey.private,
      public_key: sshKey.public,
      force: 'true'
    })))

    const firstSr = srsObjects[0]
    const firstVM = await _importGlusterVM.call(this, xapi, template, firstSr)
    $onFailure(() => xapi.deleteVm(firstVM, true))
    const copiedVms = await asyncMap(srsObjects.slice(1), sr =>
      copyVm(xapi, firstVM, sr)::tap(({ vm }) =>
        $onFailure(() => xapi.deleteVm(vm))
      )
    )
    const vmsAndSrs = [{
      vm: firstVM,
      sr: firstSr
    }].concat(copiedVms)
    let arbiter = null
    if (srs.length === 2) {
      const sr = firstSr
      const arbiterIP = NETWORK_PREFIX + (vmIpLastNumber++)
      const arbiterVm = await xapi.copyVm(firstVM, sr)
      $onFailure(() => xapi.deleteVm(arbiterVm, true))
      arbiter = await _prepareGlusterVm2(xapi, sr, arbiterVm, xosanNetwork, arbiterIP, '_arbiter', false)
    }
    const ipAndHosts = await asyncMap(vmsAndSrs, vmAndSr => _prepareGlusterVm2(xapi, vmAndSr.sr, vmAndSr.vm, xosanNetwork, NETWORK_PREFIX + (vmIpLastNumber++)))
    const firstIpAndHost = ipAndHosts[0]
    const glusterEndpoint = { xapi, host: firstIpAndHost.host, addresses: map(ipAndHosts, ih => ih.address) }
    await configureGluster(redundancy, ipAndHosts, glusterEndpoint, glusterType, arbiter)
    debug('xosan gluster volume started')
    const config = { server: firstIpAndHost.address + ':/xosan', backupserver: ipAndHosts[1].address }
    const xosanSr = await xapi.call('SR.create', firstSr.$PBDs[0].$host.$ref, config, 0, 'XOSAN', 'XOSAN', 'xosan', '', true, {})
    const nodes = ipAndHosts.map(param => ({ host: param.host.$id, vm: { id: param.vm.$id, ip: param.address } }))
    if (arbiter) {
      nodes.push({ host: arbiter.host.$id, vm: { id: arbiter.vm.$id, ip: arbiter.address }, arbiter: true })
    }
    // we just forget because the cleanup actions will be executed before.
    $onFailure(() => xapi.forgetSr(xosanSr))
    await xapi.xo.setData(xosanSr, 'xosan_config', {
      nodes: nodes,
      template: template,
      network: xosanNetwork.$id,
      type: glusterType
    })
  } finally {
    delete CURRENTLY_CREATING_SRS[xapi.pool.$id]
  }
})

createSR.description = 'create gluster VM'
createSR.permission = 'admin'
createSR.params = {
  srs: {
    type: 'array',
    items: {
      type: 'string'
    }
  },
  pif: {
    type: 'string'
  },
  vlan: {
    type: 'string'
  },
  glusterType: {
    type: 'string'
  },
  redundancy: {
    type: 'number'
  }
}

createSR.resolve = {
  srs: ['sr', 'SR', 'administrate'],
  pif: ['pif', 'PIF', 'administrate']
}
function _getBrickName (hostname) {
  return hostname + ':/bricks/xosan/xosandir'
}

export async function replaceBrick ({ xosansr, previousBrick, newLvmSr }) {
  // TODO: a bit of user input validation on 'previousBrick', it's going to ssh
  const previousIp = previousBrick.split(':')[0]
  const xapi = this.getXapi(xosansr)
  const nodes = xapi.xo.getData(xosansr, 'xosan_config').nodes
  const newIpAddress = _findAFreeIPAddress(nodes)
  const previousNode = find(nodes, node => node.vm.ip === previousIp)
  const stayingNode = find(nodes, node => node !== previousNode)
  const glusterEndpoint = { xapi, host: xapi.getObject(stayingNode.host), addresses: map(filter(nodes, node => node !== previousNode), node => node.vm.ip) }
  await xapi.deleteVm(_getIPToVMDict(xapi, xosansr).vmForBrick(previousBrick), true)
  const arbiter = previousNode.arbiter
  let { data, newVM, addressAndHost } = await insertNewGlusterVm.call(this, xapi, xosansr, newLvmSr, arbiter ? '_arbiter' : '', glusterEndpoint, newIpAddress, !arbiter)
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume replace-brick xosan ' + previousBrick + ' ' + _getBrickName(addressAndHost.address) + ' commit force')
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml peer detach ' + previousIp, true)
  remove(data.nodes, node => node.vm.ip === previousIp)
  data.nodes.push({
    host: addressAndHost.host.$id,
    arbiter: arbiter,
    vm: { ip: addressAndHost.address, id: newVM.$id }
  })
  await xapi.xo.setData(xosansr, 'xosan_config', data)
}

replaceBrick.description = 'replaceBrick brick in gluster volume'
replaceBrick.permission = 'admin'
replaceBrick.params = {
  xosansr: { type: 'string' },
  previousBrick: { type: 'string' },
  newLvmSr: { type: 'string' }
}

replaceBrick.resolve = {
  xosansr: ['sr', 'SR', 'administrate']
}

async function _prepareGlusterVm2 (xapi, lvmSr, newVM, xosanNetwork, ipAddress, labelSuffix = '', increaseDataDisk = true) {
  const sshKey = await getOrCreateSshKey(xapi)
  const host = lvmSr.$PBDs[0].$host
  const vlan = xosanNetwork.$PIFs[0].vlan
  const parameters = {
    sr: lvmSr,
    host,
    name_label: `XOSAN - ${lvmSr.name_label} - ${host.name_label} ${labelSuffix}`,
    name_description: 'Xosan VM storing data on volume ' + lvmSr.name_label,
    // the values of the xenstore_data object *have* to be string, don't forget.
    xenstore_data: {
      'vm-data/hostname': 'XOSAN' + lvmSr.name_label + labelSuffix,
      'vm-data/sshkey': sshKey.public,
      'vm-data/ip': ipAddress,
      'vm-data/mtu': String(xosanNetwork.MTU),
      'vm-data/vlan': String(vlan || 0)
    }
  }
  return prepareGlusterVm(xapi, { vm: newVM, params: parameters }, xosanNetwork, increaseDataDisk)
}

async function _importGlusterVM (xapi, template, lvmsr) {
  const templateStream = await this.requestResource('xosan', template.id, template.version)
  // can't really copy an existing VM, because sometimes we are on a smaller disk than the existing VMs
  const newVM = await xapi.importVm(templateStream, { srId: lvmsr, type: 'xva' })
  await xapi.editVm(newVM, {
    autoPoweron: true
  })
  return newVM
}

function _findAFreeIPAddress (nodes) {
  const vmIpLastNumber = 101
  for (let i = vmIpLastNumber; i < 254; i++) {
    const candidate = NETWORK_PREFIX + i
    if (!nodes.find(n => n.vm.ip === candidate)) {
      return candidate
    }
  }
  return null
}

async function insertNewGlusterVm (xapi, xosansr, lvmsr, labelSuffix = '', glusterEndpoint = null, ipAddress = null, increaseDataDisk = true) {
  const data = xapi.xo.getData(xosansr, 'xos@an_config')
  if (ipAddress === null) {
    ipAddress = _findAFreeIPAddress(data.nodes)
  }
  const xosanNetwork = xapi.getObject(data.network)
  const srObject = xapi.getObject(lvmsr)
  // can't really copy an existing VM, because existing gluster VMs disks might too huge to be copied.
  const newVM = await _importGlusterVM.call(this, xapi, data.template, lvmsr)
  const addressAndHost = await _prepareGlusterVm2(xapi, srObject, newVM, xosanNetwork, ipAddress, labelSuffix, increaseDataDisk)
  if (!glusterEndpoint) {
    glusterEndpoint = { xapi, host: addressAndHost.host, addresses: map(data.nodes, node => node.vm.ip) }
  }
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml peer detach ' + addressAndHost.address, true)
  await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml peer probe ' + addressAndHost.address)
  return { data, newVM, addressAndHost, glusterEndpoint }
}

export const addBrick = defer.onFailure(async function ($onFailure, { xosansr, lvmsr }) {
  const xapi = this.getXapi(xosansr)
  if (CURRENTLY_CREATING_SRS[xapi.pool.$id]) {
    throw new Error('createSR is already running for this pool')
  }
  CURRENTLY_CREATING_SRS[xapi.pool.$id] = true
  try {
    const { data, newVM, addressAndHost, glusterEndpoint } = await insertNewGlusterVm.call(this, xapi, xosansr, lvmsr)
    await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume add-brick xosan replica 4 ' + _getBrickName(addressAndHost.address))
    data.nodes.push({ host: addressAndHost.host.$id, vm: { id: newVM.$id, ip: addressAndHost.address } })
    await xapi.xo.setData(xosansr, 'xosan_config', data)
    const arbiterNode = data.nodes.find(n => n['arbiter'])
    if (arbiterNode) {
      await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml volume remove-brick xosan replica 3 ' + _getBrickName(arbiterNode.vm.ip) + ' force')
      await remoteSsh(glusterEndpoint, 'gluster --mode=script --xml peer detach ' + arbiterNode.vm.ip, true)
      await xapi.deleteVm(arbiterNode.vm.id, true)
      data.nodes = data.nodes.filter(n => n !== arbiterNode)
      data.type = 'replica'
      await xapi.xo.setData(xosansr, 'xosan_config', data)
    }
  } finally {
    delete CURRENTLY_CREATING_SRS[xapi.pool.$id]
  }
})

addBrick.description = 'add brick to XOSAN SR'
addBrick.permission = 'admin'
addBrick.params = {
  xosansr: { type: 'string' },
  lvmsr: { type: 'string' }
}

addBrick.resolve = {
  xosansr: ['sr', 'SR', 'administrate'],
  lvmsr: ['sr', 'SR', 'administrate']
}

export function checkSrIsBusy ({ poolId }) {
  return !!CURRENTLY_CREATING_SRS[poolId]
}
checkSrIsBusy.description = 'checks if there is a xosan SR curently being created on the given pool id'
checkSrIsBusy.permission = 'admin'
checkSrIsBusy.params = { poolId: { type: 'string' } }

const POSSIBLE_CONFIGURATIONS = {}
POSSIBLE_CONFIGURATIONS[2] = [{ layout: 'replica_arbiter', redundancy: 3, capacity: 1 }]
POSSIBLE_CONFIGURATIONS[3] = [
  { layout: 'disperse', redundancy: 1, capacity: 2 },
  { layout: 'replica', redundancy: 3, capacity: 1 }]
POSSIBLE_CONFIGURATIONS[4] = [{ layout: 'replica', redundancy: 2, capacity: 1 }]
POSSIBLE_CONFIGURATIONS[5] = [{ layout: 'disperse', redundancy: 1, capacity: 4 }]
POSSIBLE_CONFIGURATIONS[6] = [
  { layout: 'disperse', redundancy: 2, capacity: 4 },
  { layout: 'replica', redundancy: 2, capacity: 3 },
  { layout: 'replica', redundancy: 3, capacity: 2 }]
POSSIBLE_CONFIGURATIONS[7] = [{ layout: 'disperse', redundancy: 3, capacity: 4 }]
POSSIBLE_CONFIGURATIONS[8] = [{ layout: 'replica', redundancy: 2, capacity: 4 }]
POSSIBLE_CONFIGURATIONS[9] = [
  { layout: 'disperse', redundancy: 1, capacity: 8 },
  { layout: 'replica', redundancy: 3, capacity: 3 }]
POSSIBLE_CONFIGURATIONS[10] = [
  { layout: 'disperse', redundancy: 2, capacity: 8 },
  { layout: 'replica', redundancy: 2, capacity: 5 }]
POSSIBLE_CONFIGURATIONS[11] = [{ layout: 'disperse', redundancy: 3, capacity: 8 }]
POSSIBLE_CONFIGURATIONS[12] = [
  { layout: 'disperse', redundancy: 4, capacity: 8 },
  { layout: 'replica', redundancy: 2, capacity: 6 }]
POSSIBLE_CONFIGURATIONS[13] = [{ layout: 'disperse', redundancy: 5, capacity: 8 }]
POSSIBLE_CONFIGURATIONS[14] = [
  { layout: 'disperse', redundancy: 6, capacity: 8 },
  { layout: 'replica', redundancy: 2, capacity: 7 }]
POSSIBLE_CONFIGURATIONS[15] = [
  { layout: 'disperse', redundancy: 7, capacity: 8 },
  { layout: 'replica', redundancy: 3, capacity: 5 }]
POSSIBLE_CONFIGURATIONS[16] = [{ layout: 'replica', redundancy: 2, capacity: 8 }]

export async function computeXosanPossibleOptions ({ lvmSrs }) {
  const count = lvmSrs.length
  const configurations = POSSIBLE_CONFIGURATIONS[count]
  if (!configurations) {
    return null
  }
  if (count > 0) {
    const xapi = this.getXapi(lvmSrs[0])
    const srs = map(lvmSrs, srId => xapi.getObject(srId))
    const srSizes = map(srs, sr => sr.physical_size - sr.physical_utilisation)
    const minSize = Math.min.apply(null, srSizes)
    const brickSize = (minSize - XOSAN_VM_SYSTEM_DISK_SIZE) * XOSAN_DATA_DISK_USEAGE_RATIO
    return configurations.map(conf => ({ ...conf, availableSpace: brickSize * conf.capacity }))
  }
}

computeXosanPossibleOptions.params = {
  lvmSrs: {
    type: 'array',
    items: {
      type: 'string'
    }
  }
}

// ---------------------------------------------------------------------

export async function downloadAndInstallXosanPack ({ id, version, pool }) {
  if (!this.requestResource) {
    throw new Error('requestResource is not a function')
  }

  const xapi = this.getXapi(pool.id)
  const res = await this.requestResource('xosan', id, version)

  await xapi.installSupplementalPackOnAllHosts(res)
  await xapi._updateObjectMapProperty(xapi.pool, 'other_config', {
    'xosan_pack_installation_time': String(Math.floor(Date.now() / 1e3))
  })
}

downloadAndInstallXosanPack.description = 'Register a resource via cloud plugin'

downloadAndInstallXosanPack.params = {
  id: { type: 'string' },
  version: { type: 'string' },
  pool: { type: 'string' }
}

downloadAndInstallXosanPack.resolve = {
  pool: ['pool', 'pool', 'administrate']
}

downloadAndInstallXosanPack.permission = 'admin'
