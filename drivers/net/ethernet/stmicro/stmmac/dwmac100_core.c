/*******************************************************************************
  This is the driver for the MAC 10/100 on-chip Ethernet controller
  currently tested on all the ST boards based on STb7109 and stx7200 SoCs.

  DWC Ether MAC 10/100 Universal version 4.0 has been used for developing
  this code.

  This only implements the mac core functions for this chip.

  Copyright (C) 2007-2009  STMicroelectronics Ltd

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Author: Giuseppe Cavallaro <peppe.cavallaro@st.com>
*******************************************************************************/

#include <linux/crc32.h>
#include <asm/io.h>
#include "dwmac100.h"
#include "stmmac.h"

static void dwmac100_core_init(struct mac_device_info *hw, int mtu)
{
	void __iomem *ioaddr = hw->pcsr;
	u32 value = readl(ioaddr + MAC_CONTROL);

	writel((value | MAC_CORE_INIT), ioaddr + MAC_CONTROL);

#ifdef STMMAC_VLAN_TAG_USED
	writel(ETH_P_8021Q, ioaddr + MAC_VLAN1);
#endif
}

static int dwmac100_adjust_link(struct stmmac_priv *priv)
{
	struct net_device *ndev = priv->dev;
	struct phy_device *phydev = ndev->phydev;
	int new_state = 0;
	u32 tx_cnt = priv->plat->tx_queues_to_use;
	u32 ctrl;

	ctrl = readl(priv->ioaddr + MAC_CTRL_REG);
	if (phydev->duplex != priv->oldduplex) {
		new_state = 1;
		if (!(phydev->duplex))
			ctrl &= ~MAC_CONTROL_F;
		else
			ctrl |= MAC_CONTROL_F;
		priv->oldduplex = phydev->duplex;
	}

	if (phydev->pause)
		priv->hw->mac->flow_ctrl(priv->hw, phydev->duplex, priv->flow_ctrl,
				priv->pause, tx_cnt);

	if (phydev->speed != priv->speed) {
		new_state = 1;
		switch (phydev->speed) {
		case 100:
		case 10:
			ctrl &= ~MAC_CONTROL_PS;
			break;
		default:
			netif_warn(priv, link, priv->dev,
					"broken speed: %d\n", phydev->speed);
			phydev->speed = SPEED_UNKNOWN;
			break;
		}
		if (phydev->speed != SPEED_UNKNOWN && likely(priv->plat->fix_mac_speed))
			priv->plat->fix_mac_speed(priv->plat->bsp_priv, phydev->speed);
		priv->speed = phydev->speed;
	}

	writel(ctrl, priv->ioaddr + MAC_CTRL_REG);
	return new_state;
}

static void dwmac100_dump_mac_regs(struct mac_device_info *hw, u32 *reg_space)
{
	void __iomem *ioaddr = hw->pcsr;

	reg_space[MAC_CONTROL / 4] = readl(ioaddr + MAC_CONTROL);
	reg_space[MAC_ADDR_HIGH / 4] = readl(ioaddr + MAC_ADDR_HIGH);
	reg_space[MAC_ADDR_LOW / 4] = readl(ioaddr + MAC_ADDR_LOW);
	reg_space[MAC_HASH_HIGH / 4] = readl(ioaddr + MAC_HASH_HIGH);
	reg_space[MAC_HASH_LOW / 4] = readl(ioaddr + MAC_HASH_LOW);
	reg_space[MAC_FLOW_CTRL / 4] = readl(ioaddr + MAC_FLOW_CTRL);
	reg_space[MAC_VLAN1 / 4] = readl(ioaddr + MAC_VLAN1);
	reg_space[MAC_VLAN2 / 4] = readl(ioaddr + MAC_VLAN2);
}

static int dwmac100_rx_ipc_enable(struct mac_device_info *hw)
{
	return 0;
}

static int dwmac100_irq_status(struct mac_device_info *hw,
			       struct stmmac_extra_stats *x)
{
	return 0;
}

static void dwmac100_set_umac_addr(struct mac_device_info *hw,
				   unsigned char *addr,
				   unsigned int reg_n)
{
	void __iomem *ioaddr = hw->pcsr;
	stmmac_set_mac_addr(ioaddr, addr, MAC_ADDR_HIGH, MAC_ADDR_LOW);
}

static void dwmac100_get_umac_addr(struct mac_device_info *hw,
				   unsigned char *addr,
				   unsigned int reg_n)
{
	void __iomem *ioaddr = hw->pcsr;
	stmmac_get_mac_addr(ioaddr, addr, MAC_ADDR_HIGH, MAC_ADDR_LOW);
}

static void dwmac100_set_filter(struct mac_device_info *hw,
				struct net_device *dev)
{
	void __iomem *ioaddr = (void __iomem *)dev->base_addr;
	u32 value = readl(ioaddr + MAC_CONTROL);

	if (dev->flags & IFF_PROMISC) {
		value |= MAC_CONTROL_PR;
		value &= ~(MAC_CONTROL_PM | MAC_CONTROL_IF | MAC_CONTROL_HO |
			   MAC_CONTROL_HP);
	} else if ((netdev_mc_count(dev) > HASH_TABLE_SIZE)
		   || (dev->flags & IFF_ALLMULTI)) {
		value |= MAC_CONTROL_PM;
		value &= ~(MAC_CONTROL_PR | MAC_CONTROL_IF | MAC_CONTROL_HO);
		writel(0xffffffff, ioaddr + MAC_HASH_HIGH);
		writel(0xffffffff, ioaddr + MAC_HASH_LOW);
	} else if (netdev_mc_empty(dev)) {	/* no multicast */
		value &= ~(MAC_CONTROL_PM | MAC_CONTROL_PR | MAC_CONTROL_IF |
			   MAC_CONTROL_HO | MAC_CONTROL_HP);
	} else {
		u32 mc_filter[2];
		struct netdev_hw_addr *ha;

		/* Perfect filter mode for physical address and Hash
		 * filter for multicast
		 */
		value |= MAC_CONTROL_HP;
		value &= ~(MAC_CONTROL_PM | MAC_CONTROL_PR |
			   MAC_CONTROL_IF | MAC_CONTROL_HO);

		memset(mc_filter, 0, sizeof(mc_filter));
		netdev_for_each_mc_addr(ha, dev) {
			/* The upper 6 bits of the calculated CRC are used to
			 * index the contens of the hash table
			 */
			int bit_nr = ether_crc(ETH_ALEN, ha->addr) >> 26;
			/* The most significant bit determines the register to
			 * use (H/L) while the other 5 bits determine the bit
			 * within the register.
			 */
			mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
		}
		writel(mc_filter[0], ioaddr + MAC_HASH_LOW);
		writel(mc_filter[1], ioaddr + MAC_HASH_HIGH);
	}

	writel(value, ioaddr + MAC_CONTROL);
}

static void dwmac100_flow_ctrl(struct mac_device_info *hw, unsigned int duplex,
			       unsigned int fc, unsigned int pause_time,
			       u32 tx_cnt)
{
	void __iomem *ioaddr = hw->pcsr;
	unsigned int flow = MAC_FLOW_CTRL_ENABLE;

	if (duplex)
		flow |= (pause_time << MAC_FLOW_CTRL_PT_SHIFT);
	writel(flow, ioaddr + MAC_FLOW_CTRL);
}

/* No PMT module supported on ST boards with this Eth chip. */
static void dwmac100_pmt(struct mac_device_info *hw, unsigned long mode)
{
	return;
}

static const struct stmmac_ops dwmac100_ops = {
	.core_init = dwmac100_core_init,
	.adjust_link = dwmac100_adjust_link,
	.set_mac = stmmac_set_mac,
	.rx_ipc = dwmac100_rx_ipc_enable,
	.dump_regs = dwmac100_dump_mac_regs,
	.host_irq_status = dwmac100_irq_status,
	.set_filter = dwmac100_set_filter,
	.flow_ctrl = dwmac100_flow_ctrl,
	.pmt = dwmac100_pmt,
	.set_umac_addr = dwmac100_set_umac_addr,
	.get_umac_addr = dwmac100_get_umac_addr,
};

struct mac_device_info *dwmac100_setup(void __iomem *ioaddr, int *synopsys_id)
{
	struct mac_device_info *mac;

	mac = kzalloc(sizeof(const struct mac_device_info), GFP_KERNEL);
	if (!mac)
		return NULL;

	pr_info("\tDWMAC100\n");

	mac->pcsr = ioaddr;
	mac->mac = &dwmac100_ops;
	mac->dma = &dwmac100_dma_ops;

	mac->link.port = MAC_CONTROL_PS;
	mac->link.duplex = MAC_CONTROL_F;
	mac->link.speed = 0;
	mac->mii.addr = MAC_MII_ADDR;
	mac->mii.data = MAC_MII_DATA;
	mac->mii.addr_shift = 11;
	mac->mii.addr_mask = 0x0000F800;
	mac->mii.reg_shift = 6;
	mac->mii.reg_mask = 0x000007C0;
	mac->mii.clk_csr_shift = 2;
	mac->mii.clk_csr_mask = GENMASK(5, 2);

	/* Synopsys Id is not available on old chips */
	*synopsys_id = 0;

	return mac;
}
