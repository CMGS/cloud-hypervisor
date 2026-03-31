// Copyright (c) 2021 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use log::{debug, error, info, warn};
use thiserror::Error;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK, VIRTIO_NET_CTRL_GUEST_OFFLOADS,
    VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET,
    VIRTIO_NET_CTRL_MAC_TABLE_SET, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_CTRL_RX,
    VIRTIO_NET_CTRL_RX_ALLMULTI, VIRTIO_NET_CTRL_RX_ALLUNI, VIRTIO_NET_CTRL_RX_NOBCAST,
    VIRTIO_NET_CTRL_RX_NOMULTI, VIRTIO_NET_CTRL_RX_NOUNI, VIRTIO_NET_CTRL_RX_PROMISC,
    VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, VIRTIO_NET_CTRL_VLAN_DEL, VIRTIO_NET_ERR,
    VIRTIO_NET_OK,
};
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, Bytes, GuestMemoryError};
use vm_virtio::{AccessPlatform, Translatable};

use super::virtio_features_to_tap_offload;
use crate::{GuestMemoryMmap, Tap};

#[derive(Error, Debug)]
pub enum Error {
    /// Read queue failed.
    #[error("Read queue failed")]
    GuestMemory(#[source] GuestMemoryError),
    /// No control header descriptor
    #[error("No control header descriptor")]
    NoControlHeaderDescriptor,
    /// Missing the data descriptor in the chain.
    #[error("Missing the data descriptor in the chain")]
    NoDataDescriptor,
    /// No status descriptor
    #[error("No status descriptor")]
    NoStatusDescriptor,
    /// Failed adding used index
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    /// Failed creating an iterator over the queue
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    /// Failed enabling notification for the queue
    #[error("Failed enabling notification for the queue")]
    QueueEnableNotification(#[source] virtio_queue::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlHeader {
    pub class: u8,
    pub cmd: u8,
}

// SAFETY: ControlHeader only contains a series of integers
unsafe impl ByteValued for ControlHeader {}

fn is_tolerated_ctrl_command(ctrl_hdr: ControlHeader) -> bool {
    match u32::from(ctrl_hdr.class) {
        VIRTIO_NET_CTRL_RX => matches!(
            u32::from(ctrl_hdr.cmd),
            VIRTIO_NET_CTRL_RX_PROMISC
                | VIRTIO_NET_CTRL_RX_ALLMULTI
                | VIRTIO_NET_CTRL_RX_ALLUNI
                | VIRTIO_NET_CTRL_RX_NOMULTI
                | VIRTIO_NET_CTRL_RX_NOUNI
                | VIRTIO_NET_CTRL_RX_NOBCAST
        ),
        VIRTIO_NET_CTRL_MAC => matches!(
            u32::from(ctrl_hdr.cmd),
            VIRTIO_NET_CTRL_MAC_TABLE_SET | VIRTIO_NET_CTRL_MAC_ADDR_SET
        ),
        VIRTIO_NET_CTRL_VLAN => matches!(
            u32::from(ctrl_hdr.cmd),
            VIRTIO_NET_CTRL_VLAN_ADD | VIRTIO_NET_CTRL_VLAN_DEL
        ),
        VIRTIO_NET_CTRL_ANNOUNCE => u32::from(ctrl_hdr.cmd) == VIRTIO_NET_CTRL_ANNOUNCE_ACK,
        _ => false,
    }
}

pub struct CtrlQueue {
    pub taps: Vec<Tap>,
}

impl CtrlQueue {
    pub fn new(taps: Vec<Tap>) -> Self {
        CtrlQueue { taps }
    }

    pub fn process(
        &mut self,
        mem: &GuestMemoryMmap,
        queue: &mut Queue,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<()> {
        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            let ctrl_desc = desc_chain.next().ok_or(Error::NoControlHeaderDescriptor)?;

            let ctrl_hdr: ControlHeader = desc_chain
                .memory()
                .read_obj(
                    ctrl_desc
                        .addr()
                        .translate_gva(access_platform, ctrl_desc.len() as usize),
                )
                .map_err(Error::GuestMemory)?;
            let data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;

            let data_desc_addr = data_desc
                .addr()
                .translate_gva(access_platform, data_desc.len() as usize);

            let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;

            let ok = match u32::from(ctrl_hdr.class) {
                VIRTIO_NET_CTRL_MQ => {
                    let queue_pairs = desc_chain
                        .memory()
                        .read_obj::<u16>(data_desc_addr)
                        .map_err(Error::GuestMemory)?;
                    if u32::from(ctrl_hdr.cmd) != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    } else if (queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN as u16)
                        || (queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX as u16)
                    {
                        warn!("Number of MQ pairs out of range: {queue_pairs}");
                        false
                    } else {
                        info!("Number of MQ pairs requested: {queue_pairs}");
                        true
                    }
                }
                VIRTIO_NET_CTRL_GUEST_OFFLOADS => {
                    let features = desc_chain
                        .memory()
                        .read_obj::<u64>(data_desc_addr)
                        .map_err(Error::GuestMemory)?;
                    if u32::from(ctrl_hdr.cmd) == VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET {
                        let mut ok = true;
                        for tap in self.taps.iter_mut() {
                            info!("Reprogramming tap offload with features: {features}");
                            tap.set_offload(virtio_features_to_tap_offload(features))
                                .map_err(|e| {
                                    error!("Error programming tap offload: {e:?}");
                                    ok = false;
                                })
                                .ok();
                        }
                        ok
                    } else {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    }
                }
                _ if is_tolerated_ctrl_command(ctrl_hdr) => {
                    debug!("Ignoring unsupported but tolerated control command {ctrl_hdr:?}");
                    true
                }
                _ => {
                    warn!("Unsupported command {ctrl_hdr:?}");
                    false
                }
            };

            desc_chain
                .memory()
                .write_obj(
                    if ok { VIRTIO_NET_OK } else { VIRTIO_NET_ERR } as u8,
                    status_desc
                        .addr()
                        .translate_gva(access_platform, status_desc.len() as usize),
                )
                .map_err(Error::GuestMemory)?;
            let len = ctrl_desc.len() + data_desc.len() + status_desc.len();

            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(Error::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(Error::QueueEnableNotification)?
            {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::desc::{RawDescriptor, split::Descriptor as SplitDescriptor};
    use vm_memory::GuestAddress;

    use super::*;

    const QUEUE_SIZE: u16 = 4;
    const DESC_TABLE_ADDR: u64 = 0x1000;
    const AVAIL_RING_ADDR: u64 = 0x2000;
    const USED_RING_ADDR: u64 = 0x3000;
    const CTRL_HDR_ADDR: u64 = 0x4000;
    const DATA_ADDR: u64 = 0x5000;
    const STATUS_ADDR: u64 = 0x6000;

    fn create_queue() -> Queue {
        let mut queue = Queue::new(QUEUE_SIZE).unwrap();
        queue
            .try_set_desc_table_address(GuestAddress(DESC_TABLE_ADDR))
            .unwrap();
        queue
            .try_set_avail_ring_address(GuestAddress(AVAIL_RING_ADDR))
            .unwrap();
        queue
            .try_set_used_ring_address(GuestAddress(USED_RING_ADDR))
            .unwrap();
        queue.set_size(QUEUE_SIZE);
        queue.set_ready(true);

        queue
    }

    fn write_descriptor(mem: &GuestMemoryMmap, index: u64, desc: RawDescriptor) {
        let addr = GuestAddress(DESC_TABLE_ADDR + index * size_of::<RawDescriptor>() as u64);
        mem.write_obj(desc, addr).unwrap();
    }

    fn run_ctrl_command(ctrl_hdr: ControlHeader, data: &[u8]) -> u8 {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut queue = create_queue();

        write_descriptor(
            &mem,
            0,
            RawDescriptor::from(SplitDescriptor::new(
                CTRL_HDR_ADDR,
                size_of::<ControlHeader>() as u32,
                VRING_DESC_F_NEXT as u16,
                1,
            )),
        );
        write_descriptor(
            &mem,
            1,
            RawDescriptor::from(SplitDescriptor::new(
                DATA_ADDR,
                data.len() as u32,
                VRING_DESC_F_NEXT as u16,
                2,
            )),
        );
        write_descriptor(
            &mem,
            2,
            RawDescriptor::from(SplitDescriptor::new(
                STATUS_ADDR,
                1,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        );

        mem.write_obj(ctrl_hdr, GuestAddress(CTRL_HDR_ADDR)).unwrap();
        mem.write_slice(data, GuestAddress(DATA_ADDR)).unwrap();
        mem.write_obj(0xff_u8, GuestAddress(STATUS_ADDR)).unwrap();

        mem.write_obj(0_u16.to_le(), GuestAddress(AVAIL_RING_ADDR))
            .unwrap();
        mem.write_obj(1_u16.to_le(), GuestAddress(AVAIL_RING_ADDR + 2))
            .unwrap();
        mem.write_obj(0_u16.to_le(), GuestAddress(AVAIL_RING_ADDR + 4))
            .unwrap();
        mem.write_obj(0_u16.to_le(), GuestAddress(USED_RING_ADDR))
            .unwrap();
        mem.write_obj(0_u16.to_le(), GuestAddress(USED_RING_ADDR + 2))
            .unwrap();

        CtrlQueue::new(Vec::new())
            .process(&mem, &mut queue, None)
            .unwrap();

        mem.read_obj(GuestAddress(STATUS_ADDR)).unwrap()
    }

    #[test]
    fn tolerated_control_commands_return_ok() {
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_RX as u8,
                    cmd: VIRTIO_NET_CTRL_RX_PROMISC as u8,
                },
                &[0],
            ),
            VIRTIO_NET_OK as u8
        );
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_MAC as u8,
                    cmd: VIRTIO_NET_CTRL_MAC_ADDR_SET as u8,
                },
                &[0; 6],
            ),
            VIRTIO_NET_OK as u8
        );
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_VLAN as u8,
                    cmd: VIRTIO_NET_CTRL_VLAN_ADD as u8,
                },
                &[0; 2],
            ),
            VIRTIO_NET_OK as u8
        );
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_ANNOUNCE as u8,
                    cmd: VIRTIO_NET_CTRL_ANNOUNCE_ACK as u8,
                },
                &[0],
            ),
            VIRTIO_NET_OK as u8
        );
    }

    #[test]
    fn invalid_mq_command_returns_err() {
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_MQ as u8,
                    cmd: 0xff,
                },
                &1_u16.to_le_bytes(),
            ),
            VIRTIO_NET_ERR as u8
        );
    }

    #[test]
    fn invalid_guest_offload_command_returns_err() {
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: VIRTIO_NET_CTRL_GUEST_OFFLOADS as u8,
                    cmd: 0xff,
                },
                &0_u64.to_le_bytes(),
            ),
            VIRTIO_NET_ERR as u8
        );
    }

    #[test]
    fn unknown_control_class_returns_err() {
        assert_eq!(
            run_ctrl_command(
                ControlHeader {
                    class: 0xff,
                    cmd: 0,
                },
                &[0],
            ),
            VIRTIO_NET_ERR as u8
        );
    }
}
