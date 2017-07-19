import createLogger from 'debug'
import defer from 'golike-defer'
import execa from 'execa'
import fs from 'fs-extra'
import map from 'lodash/map'
import { tap, delay } from 'promise-toolbox'
import {
  includes,
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
const GIGABYTE = 1024 * 1024 * 1024
const XOSAN_VM_SYSTEM_DISK_SIZE = 10 * GIGABYTE
const XOSAN_DATA_DISK_USEAGE_RATIO = 0.99
const XOSAN_MAX_DISK_SIZE = 2093050 * 1024 * 1024 // a bit under 2To

// TODO remove MAX_DISK_SIZE limitation. it's just used during the beta. the entire variable and its uses should disappear
const MAX_DISK_SIZE = 100 * GIGABYTE

const CURRENTLY_CREATING_SRS = {}

function _getIPToVMDict (xapi, sr) {
  const dict = {}
  const data = xapi.xo.getData(sr, 'xosan_config')
  if (data && data.nodes) {
    data.nodes.forEach(conf => {
      try {
        dict[conf.brickName] = {vm: xapi.getObject(conf.vm.id), sr: conf.underlyingSr}
      } catch (e) {
        // pass
      }
    })
  }
  return dict
}

function _getGlusterEndpoint (sr) {
  const xapi = this.getXapi(sr)
  const data = xapi.xo.getData(sr, 'xosan_config')
  if (!data || !data.nodes) {
    return null
  }
  return { xapi, hosts: map(data.nodes, node => xapi.getObject(node.host)), addresses: map(data.nodes, node => node.vm.ip) }
}

async function rateLimitedRetry (action, shouldRetry, retryCount = 20) {
  let retryDelay = 500 * (1 + Math.random() / 20)
  let result
  while (retryCount > 0 && (result = await action()) && shouldRetry(result)) {
    retryDelay *= 1.1
    debug('waiting ' + retryDelay + 'ms and retrying')
    await delay(retryDelay)
    retryCount--
  }
  return result
}

export async function getVolumeInfo ({ sr, infoType }) {
  const glusterEndpoint = this::_getGlusterEndpoint(sr)

  function parseHeal (parsed) {
    const bricks = []
    parsed['healInfo']['bricks']['brick'].forEach(brick => {
      bricks.push(brick)
      if (brick['file'] && !isArray(brick['file'])) {
        brick['file'] = [brick['file']]
      }
    })
    return {commandStatus: true, result: {bricks}}
  }

  function parseStatus (parsed) {
    const brickDictByUuid = {}
    const volume = parsed['volStatus']['volumes']['volume']
    volume['node'].forEach(node => {
      brickDictByUuid[node.peerid] = brickDictByUuid[node.peerid] || []
      brickDictByUuid[node.peerid].push(node)
    })
    return {
      commandStatus: true,
      result: {nodes: brickDictByUuid, tasks: volume['tasks']}
    }
  }

  function parseInfo (parsed) {
    const volume = parsed['volInfo']['volumes']['volume']
    volume['bricks'] = volume['bricks']['brick']
    volume['options'] = volume['options']['option']
    return {commandStatus: true, result: volume}
  }

  const infoTypes = {
    heal: {command: 'heal xosan info', handler: parseHeal},
    status: {command: 'status xosan', handler: parseStatus},
    statusDetail: {command: 'status xosan detail', handler: parseStatus},
    statusMem: {command: 'status xosan mem', handler: parseStatus},
    info: {command: 'info xosan', handler: parseInfo}
  }
  const foundType = infoTypes[infoType]
  if (!foundType) {
    throw new Error('getVolumeInfo(): "' + infoType + '" is an invalid type')
  }

  const cmdShouldRetry = result => !result['commandStatus'] && result.parsed && result.parsed['cliOutput']['opErrno'] === '30802'
  const runCmd = async () => glusterCmd(glusterEndpoint, 'volume ' + foundType.command, true)
  let commandResult = await rateLimitedRetry(runCmd, cmdShouldRetry)
  return commandResult['commandStatus'] ? foundType.handler(commandResult.parsed['cliOutput']) : commandResult
}

getVolumeInfo.description = 'info on gluster volume'
getVolumeInfo.permission = 'admin'

getVolumeInfo.params = {
  sr: {
    type: 'string'
  },
  infoType: {
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

async function callPlugin (xapi, host, command, params) {
  debug('calling plugin', host.address, command)
  return JSON.parse(await xapi.call('host.call_plugin', host.$ref, 'xosan.py', command, params))
}

async function remoteSsh (glusterEndpoint, cmd, ignoreError = false) {
  let result
  for (let address of glusterEndpoint.addresses) {
    for (let host of glusterEndpoint.hosts) {
      try {
        result = await callPlugin(glusterEndpoint.xapi, host, 'run_ssh', {destination: 'root@' + address, cmd: cmd})
        break
      } catch (exception) {
        if (exception['code'] !== 'HOST_OFFLINE') {
          throw exception
        }
      }
    }
    debug(result.command.join(' '))
    debug('=>exit:', result.exit)
    debug('=>err :', result.stderr)
    debug('=>out :', result.stdout)
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

async function glusterCmd (glusterEndpoint, cmd, ignoreError = false) {
  const result = await remoteSsh(glusterEndpoint, `gluster --mode=script --xml ${cmd}`, ignoreError)
  if (result['exit'] === 0) {
    result.parsed = parseXml(result['stdout'])
    result.commandStatus = result.parsed['cliOutput']['opRet'].trim() === '0'
    result.error = result.parsed['cliOutput']['opErrstr']
  } else {
    result.commandStatus = false
    result.error = result['stderr']
  }
  if (!ignoreError && !result.commandStatus) {
    const error = new Error(`error in gluster "${result.error}"`)
    error.result = result
    throw error
  }
  return result
}

const createNetworkAndInsertHosts = defer.onFailure(async function ($onFailure, xapi, pif, vlan) {
  let hostIpLastNumber = 1
  const xosanNetwork = await xapi.createNetwork({
    name: 'XOSAN network',
    description: 'XOSAN network',
    pifId: pif._xapiId,
    mtu: pif.mtu,
    vlan: +vlan
  })
  $onFailure(() => xapi.deleteNetwork(xosanNetwork))
  await Promise.all(xosanNetwork.$PIFs.map(pif => xapi.call('PIF.reconfigure_ip', pif.$ref, 'Static',
    NETWORK_PREFIX + (hostIpLastNumber++), '255.255.255.0', NETWORK_PREFIX + '1', '')))
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

async function _probePoolAndWaitForPresence (glusterEndpoint, addresses) {
  await Promise.all(map(addresses, address => glusterCmd(glusterEndpoint, 'peer probe ' + address)))
  function shouldRetry (peers) {
    for (let peer of peers) {
      if (peer.state === '4') {
        return true
      }
      if (peer.state === '6') {
        throw new Error(`${peer.hostname} is not in pool ("${peer.stateStr}")`)
      }
    }
    return false
  }

  const getPoolStatus = async () => (await glusterCmd(glusterEndpoint, 'pool list')).parsed.cliOutput.peerStatus.peer
  return rateLimitedRetry(getPoolStatus, shouldRetry)
}

async function configureGluster (redundancy, ipAndHosts, glusterEndpoint, glusterType, arbiter = null) {
  const configByType = {
    replica_arbiter: {
      creation: 'replica 3 arbiter 1',
      extra: []
    },
    replica: {
      creation: 'replica ' + redundancy + ' ',
      extra: ['volume set xosan cluster.data-self-heal on']
    },
    disperse: {
      creation: 'disperse ' + ipAndHosts.length + ' redundancy ' + redundancy + ' ',
      extra: []
    }
  }
  let brickVms = arbiter ? ipAndHosts.concat(arbiter) : ipAndHosts
  await _probePoolAndWaitForPresence(glusterEndpoint, map(brickVms.slice(1), bv => bv.address))
  const creation = configByType[glusterType].creation
  const volumeCreation = 'volume create xosan ' + creation + ' ' +
    brickVms.map(ipAndHost => _getBrickName(ipAndHost.address)).join(' ')
  debug('creating volume: ', volumeCreation)
  await glusterCmd(glusterEndpoint, volumeCreation)
  await glusterCmd(glusterEndpoint, 'volume set xosan network.remote-dio enable')
  await glusterCmd(glusterEndpoint, 'volume set xosan cluster.eager-lock enable')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.io-cache off')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.read-ahead off')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.quick-read off')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.strict-write-ordering off')
  await glusterCmd(glusterEndpoint, 'volume set xosan client.event-threads 8')
  await glusterCmd(glusterEndpoint, 'volume set xosan server.event-threads 8')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.io-thread-count 64')
  await glusterCmd(glusterEndpoint, 'volume set xosan performance.stat-prefetch on')
  await glusterCmd(glusterEndpoint, 'volume set xosan features.shard on')
  await glusterCmd(glusterEndpoint, 'volume set xosan features.shard-block-size 512MB')
  for (const confChunk of configByType[glusterType].extra) {
    await glusterCmd(glusterEndpoint, confChunk)
  }
  await glusterCmd(glusterEndpoint, 'volume start xosan')
}

async function testSR ({sr}) {
  const xapi = this.getXapi(sr)
  const newVM = await this::_importGlusterVM(xapi, xapi.xo.getData(sr, 'xosan_config').template, sr)
  await xapi.editVm(newVM, {
    name_label: 'XOSAN test',
    name_description: 'XOSAN test, you can delete it'
  })
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
    const firstVM = await this::_importGlusterVM(xapi, template, firstSr)
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
      arbiter = await _prepareGlusterVm(xapi, sr, arbiterVm, xosanNetwork, arbiterIP, {labelSuffix: '_arbiter', increaseDataDisk: false})
      arbiter.arbiter = true
    }
    const ipAndHosts = await asyncMap(vmsAndSrs, vmAndSr => _prepareGlusterVm(xapi, vmAndSr.sr, vmAndSr.vm, xosanNetwork,
      NETWORK_PREFIX + (vmIpLastNumber++), {maxDiskSize: MAX_DISK_SIZE}))
    const glusterEndpoint = { xapi, hosts: map(ipAndHosts, ih => ih.host), addresses: map(ipAndHosts, ih => ih.address) }
    await configureGluster(redundancy, ipAndHosts, glusterEndpoint, glusterType, arbiter)
    debug('xosan gluster volume started')
    const config = { server: ipAndHosts[0].address + ':/xosan', backupserver: ipAndHosts[1].address }
    const xosanSr = await xapi.call('SR.create', firstSr.$PBDs[0].$host.$ref, config, 0, 'XOSAN', 'XOSAN', 'xosan', '', true, {})
    // we just forget because the cleanup actions are stacked in the $onFailure system
    $onFailure(() => xapi.forgetSr(xosanSr))
    if (arbiter) {
      ipAndHosts.push(arbiter)
    }
    const nodes = ipAndHosts.map(param => ({
      brickName: _getBrickName(param.address),
      host: param.host.$id,
      vm: {id: param.vm.$id, ip: param.address},
      underlyingSr: param.underlyingSr.$id,
      arbiter: !!param['arbiter']
    }))
    await xapi.xo.setData(xosanSr, 'xosan_config', {
      nodes: nodes,
      template: template,
      network: xosanNetwork.$id,
      type: glusterType,
      redundancy
    })
    await this::testSR({sr: xosanSr})
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
  const stayingNodes = filter(nodes, node => node !== previousNode)
  const glusterEndpoint = { xapi, hosts: map(stayingNodes, node => xapi.getObject(node.host)), addresses: map(stayingNodes, node => node.vm.ip) }
  const previousVMEntry = _getIPToVMDict(xapi, xosansr)[previousBrick]
  const arbiter = previousNode.arbiter
  let { data, newVM, addressAndHost } = await this::insertNewGlusterVm(xapi, xosansr, newLvmSr,
    {labelSuffix: arbiter ? '_arbiter' : '', glusterEndpoint, newIpAddress, increaseDataDisk: !arbiter})
  const brickName = _getBrickName(addressAndHost.address)
  await glusterCmd(glusterEndpoint, `volume replace-brick xosan ${previousBrick} ${brickName} commit force`)
  await glusterCmd(glusterEndpoint, 'peer detach ' + previousIp, true)
  remove(data.nodes, node => node.vm.ip === previousIp)
  data.nodes.push({
    brickName: brickName,
    host: addressAndHost.host.$id,
    arbiter: arbiter,
    vm: {ip: addressAndHost.address, id: newVM.$id},
    underlyingSr: newLvmSr
  })
  await xapi.xo.setData(xosansr, 'xosan_config', data)
  if (previousVMEntry) {
    await xapi.deleteVm(previousVMEntry.vm, true)
  }
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

async function _prepareGlusterVm (xapi, lvmSr, newVM, xosanNetwork, ipAddress, {labelSuffix = '', increaseDataDisk = true, maxDiskSize = Infinity}) {
  const host = lvmSr.$PBDs[0].$host
  const xenstoreData = {
    'vm-data/hostname': 'XOSAN' + lvmSr.name_label + labelSuffix,
    'vm-data/sshkey': (await getOrCreateSshKey(xapi)).public,
    'vm-data/ip': ipAddress,
    'vm-data/mtu': String(xosanNetwork.MTU),
    'vm-data/vlan': String(xosanNetwork.$PIFs[0].vlan || 0)
  }
  const ip = ipAddress
  const sr = xapi.getObject(lvmSr.$id)
  // refresh the object so that sizes are correct
  await xapi._waitObjectState(sr.$id, sr => Boolean(sr.$PBDs))
  const firstVif = newVM.$VIFs[0]
  if (xosanNetwork.$id !== firstVif.$network.$id) {
    try {
      await xapi.call('VIF.move', firstVif.$ref, xosanNetwork.$ref)
    } catch (error) {
      if (error.code === 'MESSAGE_METHOD_UNKNOWN') {
        // VIF.move has been introduced in xenserver 7.0
        await xapi.deleteVif(firstVif.$id)
        await xapi.createVif(newVM.$id, xosanNetwork.$id, firstVif)
      }
    }
  }
  const newMemory = 2 * GIGABYTE
  await xapi.editVm(newVM, {
    name_label: `XOSAN - ${lvmSr.name_label} - ${host.name_label} ${labelSuffix}`,
    name_description: 'Xosan VM storage',
    // https://bugs.xenserver.org/browse/XSO-762
    memory_static_max: newMemory,
    memory_dynamic_max: newMemory
  })
  await xapi.call('VM.set_xenstore_data', newVM.$ref, xenstoreData)
  if (increaseDataDisk) {
    const dataDisk = newVM.$VBDs.map(vbd => vbd.$VDI).find(vdi => vdi && vdi.name_label === 'xosan_data')
    const srFreeSpace = sr.physical_size - sr.physical_utilisation
    // we use a percentage because it looks like the VDI overhead is proportional
    const newSize = floor2048(Math.min(maxDiskSize, (srFreeSpace + dataDisk.virtual_size) * XOSAN_DATA_DISK_USEAGE_RATIO))
    // TODO remove MAX_DISK_SIZE limitation. it's just used during the beta
    await xapi._resizeVdi(dataDisk, Math.min(newSize, XOSAN_MAX_DISK_SIZE))
  }
  await xapi.startVm(newVM)
  debug('waiting for boot of ', ip)
  // wait until we find the assigned IP in the networks, we are just checking the boot is complete
  const vmIsUp = vm => Boolean(vm.$guest_metrics && includes(vm.$guest_metrics.networks, ip))
  const vm = await xapi._waitObjectState(newVM.$id, vmIsUp)
  debug('booted ', ip)
  return { address: ip, host, vm, underlyingSr: lvmSr }
}

async function _importGlusterVM (xapi, template, lvmsrId) {
  const templateStream = await this.requestResource('xosan', template.id, template.version)
  // can't really copy an existing VM, because sometimes we are on a smaller disk than the existing VMs
  const newVM = await xapi.importVm(templateStream, { srId: lvmsrId, type: 'xva' })
  await xapi.editVm(newVM, {
    autoPoweron: true
  })
  return newVM
}

function _findAFreeIPAddress (nodes) {
  return _findIPAddressOutsideList(map(nodes, n => n.vm.ip))
}

function _findIPAddressOutsideList (reservedList) {
  const vmIpLastNumber = 101
  for (let i = vmIpLastNumber; i < 255; i++) {
    const candidate = NETWORK_PREFIX + i
    if (!reservedList.find(a => a === candidate)) {
      return candidate
    }
  }
  return null
}

async function insertNewGlusterVm (xapi, xosansr, lvmsrId, {labelSuffix = '', glusterEndpoint = null, ipAddress = null,
  increaseDataDisk = true, maxDiskSize = Infinity}) {
  const data = xapi.xo.getData(xosansr, 'xosan_config')
  if (ipAddress === null) {
    ipAddress = _findAFreeIPAddress(data.nodes)
  }
  const xosanNetwork = xapi.getObject(data.network)
  const srObject = xapi.getObject(lvmsrId)
  // can't really copy an existing VM, because existing gluster VMs disks might too large to be copied.
  const newVM = await this::_importGlusterVM(xapi, data.template, lvmsrId)
  const addressAndHost = await _prepareGlusterVm(xapi, srObject, newVM, xosanNetwork, ipAddress, {labelSuffix, increaseDataDisk, maxDiskSize})
  if (!glusterEndpoint) {
    glusterEndpoint = this::_getGlusterEndpoint(xosansr)
  }
  await _probePoolAndWaitForPresence(glusterEndpoint, [addressAndHost.address])
  return { data, newVM, addressAndHost, glusterEndpoint }
}

export const addBricks = defer.onFailure(async function ($onFailure, { xosansr, lvmsrs }) {
  const xapi = this.getXapi(xosansr)
  if (CURRENTLY_CREATING_SRS[xapi.pool.$id]) {
    throw new Error('createSR is already running for this pool')
  }
  CURRENTLY_CREATING_SRS[xapi.pool.$id] = true
  try {
    const data = xapi.xo.getData(xosansr, 'xosan_config')
    const usedAddresses = map(data.nodes, n => n.vm.ip)
    const glusterEndpoint = this::_getGlusterEndpoint(xosansr)
    const newAddresses = []
    const newNodes = []
    for (let newSr of lvmsrs) {
      const ipAddress = _findIPAddressOutsideList(usedAddresses.concat(newAddresses))
      newAddresses.push(ipAddress)
      // TODO remove MAX_DISK_SIZE limitation. it's just used during the beta
      const { newVM, addressAndHost } = await this::insertNewGlusterVm(xapi, xosansr, newSr, {ipAddress, maxDiskSize: MAX_DISK_SIZE})
      $onFailure(() => glusterCmd(glusterEndpoint, 'peer detach ' + ipAddress, true))
      $onFailure(() => xapi.deleteVm(newVM, true))
      const brickName = _getBrickName(ipAddress)
      newNodes.push({ brickName, host: addressAndHost.host.$id, vm: { id: newVM.$id, ip: ipAddress }, underlyingSr: newSr })
    }
    const replicaPart = data.type === 'replica_arbiter' || data.type === 'replica' ? `replica ${data.nodes.length + lvmsrs.length}` : ''
    await glusterCmd(glusterEndpoint, `volume add-brick xosan ${replicaPart} ${newNodes.map(n => n.brickName).join(' ')}`)
    data.nodes = data.nodes.concat(newNodes)
    await xapi.xo.setData(xosansr, 'xosan_config', data)
    const arbiterNode = data.nodes.find(n => n['arbiter'])
    if (arbiterNode) {
      await glusterCmd(glusterEndpoint, `volume remove-brick xosan replica ${data.nodes.length - 1} ${_getBrickName(arbiterNode.vm.ip)} force`)
      await glusterCmd(glusterEndpoint, 'peer detach ' + arbiterNode.vm.ip, true)
      await xapi.deleteVm(arbiterNode.vm.id, true)
      data.nodes = data.nodes.filter(n => n !== arbiterNode)
      data.type = 'replica'
      await xapi.xo.setData(xosansr, 'xosan_config', data)
    }
  } finally {
    delete CURRENTLY_CREATING_SRS[xapi.pool.$id]
  }
})

addBricks.description = 'add brick to XOSAN SR'
addBricks.permission = 'admin'
addBricks.params = {
  xosansr: { type: 'string' },
  lvmsrs: {
    type: 'array',
    items: {
      type: 'string'
    } }
}

addBricks.resolve = {
  xosansr: ['sr', 'SR', 'administrate'],
  lvmsrs: ['sr', 'SR', 'administrate']
}

export const removeBricks = defer.onFailure(async function ($onFailure, { xosansr, bricks }) {
  const xapi = this.getXapi(xosansr)
  if (CURRENTLY_CREATING_SRS[xapi.pool.$id]) {
    throw new Error('this there is already a XOSAN operation running on this pool')
  }
  CURRENTLY_CREATING_SRS[xapi.pool.$id] = true
  try {
    const data = xapi.xo.getData(xosansr, 'xosan_config')
    const ips = map(bricks, b => b.split(':')[0])
    const glusterEndpoint = this::_getGlusterEndpoint(xosansr)
    const dict = _getIPToVMDict(xapi, xosansr)
    const brickVMs = map(bricks, b => dict[b])
    const replicaPart = data.type === 'replica_arbiter' || data.type === 'replica' ? `replica ${data.nodes.length - bricks.length}` : ''
    await glusterCmd(glusterEndpoint, `volume remove-brick xosan ${replicaPart} ${bricks.join(' ')} force`)
    remove(data.nodes, node => ips.includes(node.vm.ip))
    await xapi.xo.setData(xosansr, 'xosan_config', data)
    await asyncMap(brickVMs, vm => xapi.deleteVm(vm.vm, true))
  } finally {
    delete CURRENTLY_CREATING_SRS[xapi.pool.$id]
  }
})

removeBricks.description = 'remove brick from XOSAN SR'
removeBricks.permission = 'admin'
removeBricks.params = {
  xosansr: { type: 'string' },
  bricks: {
    type: 'array',
    items: { type: 'string' }
  }
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
POSSIBLE_CONFIGURATIONS[4] = [{ layout: 'replica', redundancy: 2, capacity: 2 }]
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
    // TODO remove MAX_DISK_SIZE limitation. it's just used during the beta
    const minSize = Math.min.apply(null, srSizes.concat(MAX_DISK_SIZE))
    const brickSize = Math.floor((minSize - XOSAN_VM_SYSTEM_DISK_SIZE) * XOSAN_DATA_DISK_USEAGE_RATIO)
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
