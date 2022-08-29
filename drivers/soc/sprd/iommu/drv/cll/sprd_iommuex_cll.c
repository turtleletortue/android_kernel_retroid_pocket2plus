#include "sprd_iommuex_cll.h"

struct sprd_iommu_func_tbl iommuex_func_tbl = {
	sprd_iommuex_cll_init,
	sprd_iommuex_cll_uninit,

	sprd_iommuex_cll_map,
	sprd_iommuex_cll_unmap,

	sprd_iommuex_cll_enable,
	sprd_iommuex_cll_disable,

	sprd_iommuex_cll_suspend,
	sprd_iommuex_cll_resume,
	sprd_iommuex_cll_release,
	sprd_iommuex_cll_reset,
	sprd_iommuex_cll_set_bypass,
	sprd_iommuex_cll_virt_to_phy,
	sprd_iommuex_cll_unmap_orphaned,
};

u32 sprd_iommuex_cll_init(struct sprd_iommu_init_param *p_init_param,
						sprd_iommu_hdl p_iommu_hdl)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id, iommu_type;
	u8 pa_out_range_r_en = 0;
	u8 pa_out_range_w_en = 0;
	u8 va_out_range_r_en = 0;
	u8 va_out_range_w_en = 0;
	u8 invalid_r_en = 0;
	u8 invalid_w_en = 0;
	u8 unsecure_r_en = 0;
	u8 unsecure_w_en = 0;
	unsigned int pagt_size = 0;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;

	p_iommu_priv = (struct sprd_iommuex_priv *)sprd_malloc(
					sizeof(struct sprd_iommuex_priv));
	sprd_memset((void *)p_iommu_priv, 0, sizeof(struct sprd_iommuex_priv));
	p_iommu_priv->master_reg_addr = p_init_param->master_reg_addr;
	p_iommu_priv->mmu_reg_addr = p_init_param->ctrl_reg_addr;
	iommu_id = p_init_param->iommu_id;
	iommu_type = p_init_param->iommu_type;
	p_iommu_priv->iommu_type = p_init_param->iommu_type;
	p_iommu_priv->iommu_id = p_init_param->iommu_id;
	p_iommu_priv->chip = p_init_param->chip;
	p_iommu_priv->vpn_base_addr = p_init_param->fm_base_addr;
	p_iommu_priv->vpn_range = p_init_param->fm_ram_size;

	/*
	*in acual use:jpg/gsp 256M,cpp 128M,DISP 128M(sharkl2) 256M(isharkl2),
	*vsp 256M, dcam 64M
	*/
	pagt_size = (p_iommu_priv->vpn_range / MMU_MAPING_PAGESIZE) * 4;
	if (p_init_param->pagt_base_ddr > 0) {
		p_iommu_priv->pagt_base_phy_ddr = p_init_param->pagt_base_ddr;
		p_iommu_priv->pagt_ddr_size = p_init_param->pagt_ddr_size;
		p_iommu_priv->pagt_base_ddr =
			(ulong)ioremap_nocache(p_iommu_priv->pagt_base_phy_ddr,
					p_iommu_priv->pagt_ddr_size);
	} else {
		p_iommu_priv->pagt_base_phy_ddr = 0;
		p_iommu_priv->pagt_ddr_size = 0;
		p_iommu_priv->pagt_base_ddr = 0;
	}

	p_iommu_priv->pgt_size = pagt_size;
	if (p_iommu_priv->pagt_base_phy_ddr > 0) {
		/*page table in ddr use reserved memory*/
		p_iommu_priv->ppn_base_addr =
			p_iommu_priv->pagt_base_ddr;
	} else {
		p_iommu_priv->ppn_base_addr =
			(ulong)sprd_aligned_malloc(pagt_size,
					MMU_MAPING_PAGESIZE);
	}

	if (iommu_id == IOMMU_EX_ISP)
		sprd_memset((void *)p_iommu_priv->ppn_base_addr, 0x0, pagt_size);
	else
		sprd_memset((void *)p_iommu_priv->ppn_base_addr, 0xff, pagt_size);

	p_iommu_priv->ram_clk_div = p_init_param->ram_clk_div;

	p_iommu_priv->default_addr = p_init_param->faultpage_addr;
	p_iommu_priv->map_cnt = 0;
	p_iommu_priv->mini_ppn1 = p_init_param->mini_ppn1;
	p_iommu_priv->ppn1_range = p_init_param->ppn1_range;
	p_iommu_priv->mini_ppn2 = p_init_param->mini_ppn2;
	p_iommu_priv->ppn2_range = p_init_param->ppn2_range;

	/*enable interrupt cpp must set 0*/
	if (iommu_id == IOMMU_EX_CPP) {
		pa_out_range_r_en = 1;
		pa_out_range_w_en = 1;
		va_out_range_r_en = 1;
		va_out_range_w_en = 1;
		invalid_r_en = 1;
		invalid_w_en = 1;
		unsecure_r_en = 1;
		unsecure_w_en = 1;
	}
	p_iommu_priv->st_interrupt.pa_out_range_r_en = pa_out_range_r_en;
	p_iommu_priv->st_interrupt.pa_out_range_w_en = pa_out_range_w_en;
	p_iommu_priv->st_interrupt.va_out_range_r_en = va_out_range_r_en;
	p_iommu_priv->st_interrupt.va_out_range_w_en = va_out_range_w_en;
	p_iommu_priv->st_interrupt.invalid_r_en = invalid_r_en;
	p_iommu_priv->st_interrupt.invalid_w_en = invalid_w_en;
	p_iommu_priv->st_interrupt.unsecure_r_en = unsecure_r_en;
	p_iommu_priv->st_interrupt.unsecure_w_en = unsecure_w_en;

	p_iommu_data->p_priv = (void *)(p_iommu_priv);
	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_uninit(sprd_iommu_hdl  p_iommu_hdl)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id, iommu_type;
	u8 pa_out_range_r_en = 0;
	u8 pa_out_range_w_en = 0;
	u8 va_out_range_r_en = 0;
	u8 va_out_range_w_en = 0;
	u8 invalid_r_en = 0;
	u8 invalid_w_en = 0;
	u8 unsecure_r_en = 0;
	u8 unsecure_w_en = 0;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);

	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	if (iommu_id == IOMMU_EX_CPP) {
		pa_out_range_r_en = 1;
		pa_out_range_w_en = 1;
		va_out_range_r_en = 1;
		va_out_range_w_en = 1;
		invalid_r_en = 1;
		invalid_w_en = 1;
		unsecure_r_en = 1;
		unsecure_w_en = 1;
	}

	mmu_ex_enable(p_iommu_priv->mmu_reg_addr, iommu_id, 0);
	if (p_iommu_priv->pagt_base_phy_ddr > 0)
		iounmap((void __iomem *)p_iommu_priv->pagt_base_ddr);
	else
		sprd_free((void *)p_iommu_priv->ppn_base_addr);

	p_iommu_priv->ppn_base_addr = 0;

	sprd_memset(p_iommu_data->p_priv, 0, sizeof(struct sprd_iommuex_priv));
	sprd_free(p_iommu_data->p_priv);
	p_iommu_data->p_priv = NULL;

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_reg_authority(sprd_iommu_hdl  p_iommu_hdl, u8 authority)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 ret = 0;
	u32 iommu_id = -1;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	iommu_id = p_iommu_priv->iommu_id;
	mmu_ex_reg_authority(p_iommu_priv->mmu_reg_addr, iommu_id, authority);
	return ret;
}

void sprd_iommuex_flush_pgt(ulong ppn_base, u32 start_entry, u32 end_entry)
{
#ifdef CONFIG_64BIT
#ifdef CONFIG_ARM64
	__dma_flush_area((void *)(ppn_base +
		start_entry * 4),
		end_entry * 4);
#else
	/*x86*/
	clflush_cache_range((void *)(ppn_base +
		start_entry * 4),
		(end_entry - start_entry) * 4);
#endif
#else
	dmac_flush_range((void *)(ppn_base +
		start_entry * 4),
		(void *)(ppn_base +
		end_entry * 4));
#endif
}

u32 sprd_iommuex_cll_map(sprd_iommu_hdl  p_iommu_hdl,
				struct sprd_iommu_map_param *p_map_param)
{
	u32 entry_index = 0;
	u32 valid_page_entrys = 0;
	ulong phy_addr = 0;
	u32 vir_base_entry = 0;
	u32 total_page_entrys = 0;
	u32 align_map_size = 0;
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	struct scatterlist *sg;
	u32 sg_index = 0;
	u32 iommu_id = -1;
	u32 iommu_type = -1;

	if ((p_iommu_hdl == NULL) || (p_map_param == NULL))
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);

	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	vir_base_entry = (u32)VIR_TO_ENTRY_IDX(p_map_param->start_virt_addr,
					      p_iommu_priv->vpn_base_addr);
	total_page_entrys = vir_base_entry;

	for_each_sg(p_map_param->p_sg_table->sgl, sg,
		     p_map_param->p_sg_table->nents, sg_index) {

		align_map_size = MAP_SIZE_PAGE_ALIGN_UP(sg->length);
		valid_page_entrys  = (u32)SIZE_TO_ENTRYS(align_map_size);

		for (entry_index = 0; entry_index < valid_page_entrys;
		      entry_index++) {
			phy_addr = sg_to_phys(sg) +
				(entry_index << MMU_MAPING_PAGESIZE_SHIFFT);

			phy_addr = phy_addr >> MMU_MAPING_PAGESIZE_SHIFFT;
			/*isp_iommu the hightest bit 1 indicates valid addr*/
			if (iommu_id == IOMMU_EX_ISP)
				phy_addr |= 0x80000000;

			mmu_ex_write_pate_totable(p_iommu_priv->ppn_base_addr,
				total_page_entrys + entry_index, phy_addr);
		}
		total_page_entrys += entry_index;
	}

	if (p_iommu_priv->pagt_base_phy_ddr == 0)
		sprd_iommuex_flush_pgt(p_iommu_priv->ppn_base_addr,
				       vir_base_entry,
				       total_page_entrys);

	sprd_iommuex_cll_enable(p_iommu_hdl);

	/*we must update the tlb rame,because prefetch may be have taken addr
	*information before we map this time
	*/
	if (iommu_id == IOMMU_EX_ISP) {
		mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 0, 0);
		mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 1, 1);
	} else
		mmu_ex_update(p_iommu_priv->mmu_reg_addr, iommu_id, iommu_type);
	/*for sharkle dcam_if r4p0*/
	mmu_ex_frc_copy(p_iommu_priv->master_reg_addr, iommu_id, iommu_type);

	p_iommu_priv->map_cnt++;

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_unmap(sprd_iommu_hdl p_iommu_hdl,
			struct sprd_iommu_unmap_param *p_unmap_param)
{
	u32 valid_page_entrys = 0;
	ulong vir_base_entry = 0;
	u64 align_map_size = 0;
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id = -1;
	u32 iommu_type = -1;

	if ((p_iommu_hdl == NULL) || (p_unmap_param == NULL))
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	vir_base_entry = (ulong)VIR_TO_ENTRY_IDX(
					p_unmap_param->start_virt_addr,
					p_iommu_priv->vpn_base_addr);


	align_map_size = MAP_SIZE_PAGE_ALIGN_UP(p_unmap_param->total_map_size);
	valid_page_entrys  = (u32)SIZE_TO_ENTRYS(align_map_size);

	if (iommu_id == IOMMU_EX_ISP) {
		sprd_memset((void *)(p_iommu_priv->ppn_base_addr +
				vir_base_entry * 4),
				0x0, valid_page_entrys * 4);
		if (p_iommu_priv->pagt_base_phy_ddr == 0)
			sprd_iommuex_flush_pgt(p_iommu_priv->ppn_base_addr,
					       vir_base_entry,
					       vir_base_entry +
					       valid_page_entrys);

		if (p_unmap_param->ch_type == EX_CH_READ ||
		   p_unmap_param->ch_type == EX_CH_WRITE) {
			mmu_ex_tlb_update(p_iommu_priv->mmu_reg_addr,
				p_unmap_param->ch_type, p_unmap_param->ch_id);
		} else {
			mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 0, 0);
			mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 1, 1);
		}
	} else {
		sprd_memset((void *)(p_iommu_priv->ppn_base_addr +
				vir_base_entry * 4),
				0xFF, valid_page_entrys * 4);
		if (p_iommu_priv->pagt_base_phy_ddr == 0)
			sprd_iommuex_flush_pgt(p_iommu_priv->ppn_base_addr,
					       vir_base_entry,
					       vir_base_entry +
					       valid_page_entrys);
		mmu_ex_update(p_iommu_priv->mmu_reg_addr, iommu_id, iommu_type);
	}

	p_iommu_priv->map_cnt--;

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_unmap_orphaned(sprd_iommu_hdl p_iommu_hdl,
			struct sprd_iommu_unmap_param *p_unmap_param)
{
	u32 valid_page_entrys = 0;
	ulong vir_base_entry = 0;
	u64 align_map_size = 0;
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id = -1;
	u32 iommu_type = -1;

	if ((p_iommu_hdl == NULL) || (p_unmap_param == NULL))
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	vir_base_entry = (ulong)VIR_TO_ENTRY_IDX(
					p_unmap_param->start_virt_addr,
					p_iommu_priv->vpn_base_addr);


	align_map_size = MAP_SIZE_PAGE_ALIGN_UP(p_unmap_param->total_map_size);
	valid_page_entrys  = (u32)SIZE_TO_ENTRYS(align_map_size);

	if (iommu_id == IOMMU_EX_ISP) {
		sprd_memset((void *)(p_iommu_priv->ppn_base_addr +
				vir_base_entry * 4),
				0x0, valid_page_entrys * 4);
	} else {
		sprd_memset((void *)(p_iommu_priv->ppn_base_addr +
				vir_base_entry * 4),
				0xFF, valid_page_entrys * 4);
	}

	if (p_iommu_priv->pagt_base_phy_ddr == 0)
		sprd_iommuex_flush_pgt(p_iommu_priv->ppn_base_addr,
				       vir_base_entry,
				       vir_base_entry +
				       valid_page_entrys);

	p_iommu_priv->map_cnt--;

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_enable(sprd_iommu_hdl p_iommu_hdl)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id = -1;
	ulong addr_range = 0;
	ulong pgt_addr_phy = 0;
	ulong fault_page = 0;
	u32 iommu_type = -1;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	if (mmu_ex_check_en(p_iommu_priv->mmu_reg_addr, iommu_id))
		goto exit;

	/*config first vpn*/
	if (p_iommu_priv->pagt_base_phy_ddr > 0)
		pgt_addr_phy = p_iommu_priv->pagt_base_phy_ddr;
	else
		pgt_addr_phy = virt_to_phys(
					(void *)p_iommu_priv->ppn_base_addr);

	mmu_ex_first_vpn(p_iommu_priv->mmu_reg_addr, iommu_id,
		p_iommu_priv->vpn_base_addr);
	mmu_ex_first_ppn(p_iommu_priv->mmu_reg_addr, iommu_id, pgt_addr_phy);

	fault_page = p_iommu_priv->default_addr;
	mmu_ex_default_ppn(p_iommu_priv->mmu_reg_addr, iommu_id, fault_page);

	if (iommu_id != IOMMU_EX_ISP) {
		if (iommu_id == IOMMU_EX_DISP)
			mmu_ex_vpn_range(p_iommu_priv->mmu_reg_addr,
			    iommu_id, (p_iommu_priv->vpn_range >> 12) - 1);

		/*vpn_range temporary use default value*/
		if (p_iommu_priv->mini_ppn1 > 0)
			mmu_ex_mini_ppn1(p_iommu_priv->mmu_reg_addr, iommu_id,
				p_iommu_priv->mini_ppn1);

		if (p_iommu_priv->ppn1_range > 0) {
			addr_range = 0;
			addr_range = (p_iommu_priv->ppn1_range +
					(1<<20) - 1) & (~((1<<20) - 1));
			mmu_ex_mini_ppn1(p_iommu_priv->mmu_reg_addr, iommu_id,
				p_iommu_priv->ppn1_range);
		}

		if (p_iommu_priv->mini_ppn2 > 0)
			mmu_ex_mini_ppn2(p_iommu_priv->mmu_reg_addr, iommu_id,
				p_iommu_priv->mini_ppn2);

		if (p_iommu_priv->ppn2_range > 0) {
			addr_range = 0;
			addr_range = (p_iommu_priv->ppn2_range +
					(1<<20) - 1) & (~((1<<20) - 1));
			mmu_ex_mini_ppn2(p_iommu_priv->mmu_reg_addr, iommu_id,
				p_iommu_priv->ppn2_range);
		}
		/*config update arqos,access ddr priority,default 7*/
		mmu_ex_pt_update_arqos(p_iommu_priv->mmu_reg_addr, 7);
	} else {
		/*isp iommu need config page table size*/
		mmuex_pagetable_size(p_iommu_priv->mmu_reg_addr,
			p_iommu_priv->pgt_size - 1);
	}

	mmu_ex_vaorbypass_clkgate_enable_combined(p_iommu_priv->mmu_reg_addr,
		iommu_id);
exit:
	/*for sharkle dcam_if r4p0*/
	mmu_ex_frc_copy(p_iommu_priv->master_reg_addr, iommu_id, iommu_type);

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_disable(sprd_iommu_hdl  p_iommu_hdl)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;
	u32 iommu_id = -1;
	u32 iommu_type = -1;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	iommu_id = p_iommu_priv->iommu_id;
	iommu_type = p_iommu_priv->iommu_type;

	mmu_ex_first_vpn(p_iommu_priv->mmu_reg_addr, iommu_id, 0);
	mmu_ex_first_ppn(p_iommu_priv->mmu_reg_addr, iommu_id, 0);
	mmu_ex_default_ppn(p_iommu_priv->mmu_reg_addr, iommu_id, 0);
	if (iommu_id != IOMMU_EX_ISP) {

		if (p_iommu_priv->mini_ppn1 > 0)
			mmu_ex_mini_ppn1(p_iommu_priv->mmu_reg_addr,
				iommu_id, 0);

		if (p_iommu_priv->ppn1_range > 0)
			mmu_ex_mini_ppn1(p_iommu_priv->mmu_reg_addr,
				iommu_id, 0x1fff);

		if (p_iommu_priv->mini_ppn2 > 0)
			mmu_ex_mini_ppn2(p_iommu_priv->mmu_reg_addr,
				iommu_id, 0);

		if (p_iommu_priv->ppn2_range > 0)
			mmu_ex_mini_ppn2(p_iommu_priv->mmu_reg_addr,
				iommu_id, 0x1fff);
	} else {
		/*isp iommu need config page table size*/
		mmuex_pagetable_size(p_iommu_priv->mmu_reg_addr, 0);
	}

	mmu_ex_enable(p_iommu_priv->mmu_reg_addr, iommu_id, 0);

	mmu_ex_frc_copy(p_iommu_priv->master_reg_addr, iommu_id, iommu_type);

	return SPRD_NO_ERR;
}

u32 sprd_iommuex_cll_suspend(sprd_iommu_hdl p_iommu_hdl)
{
	return 0;
}

u32 sprd_iommuex_cll_resume(sprd_iommu_hdl  p_iommu_hdl)
{
	return 0;
}

u32 sprd_iommuex_cll_release(sprd_iommu_hdl  p_iommu_hdl)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if  (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);
	p_iommu_priv->map_cnt = 0;
	return 0;
}

u32 sprd_iommuex_cll_reset(sprd_iommu_hdl  p_iommu_hdl, u32 channel_num)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if  (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);

	sprd_iommuex_cll_enable(p_iommu_hdl);

	if (p_iommu_priv->iommu_id == IOMMU_EX_ISP) {
		mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 0, 0);
		mmuex_tlb_enable(p_iommu_priv->mmu_reg_addr, 1, 1);
	} else
		mmu_ex_update(p_iommu_priv->mmu_reg_addr,
			p_iommu_priv->iommu_id,
			p_iommu_priv->iommu_type);

	return 0;
}

u32 sprd_iommuex_cll_set_bypass(sprd_iommu_hdl  p_iommu_hdl, bool vaor_bp_en)
{
	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if  (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);

	mmu_ex_vaout_bypass_enable(p_iommu_priv->mmu_reg_addr,
				   p_iommu_priv->iommu_id,
				   p_iommu_priv->iommu_type,
				   vaor_bp_en);
	return 0;
}

u32  sprd_iommuex_cll_virt_to_phy(sprd_iommu_hdl p_iommu_hdl,
			u64 virt_addr, u64 *dest_addr)
{
	u64 entry_index = 0;
	u64 phy_page_addr = 0;
	u64 page_in_offset = 0;
	u64 real_phy_addr = 0;

	struct sprd_iommu_widget *p_iommu_data = NULL;
	struct sprd_iommuex_priv *p_iommu_priv = NULL;

	if (p_iommu_hdl == NULL)
		return SPRD_ERR_INVALID_PARAM;

	p_iommu_data = (struct sprd_iommu_widget *)p_iommu_hdl;
	if  (p_iommu_data->p_priv == NULL)
		return SPRD_ERR_INITIALIZED;

	p_iommu_priv = (struct sprd_iommuex_priv *)(p_iommu_data->p_priv);

	entry_index = VIR_TO_ENTRY_IDX(virt_addr,
				p_iommu_priv->vpn_base_addr);
	phy_page_addr = mmu_ex_read_page_entry(p_iommu_priv->ppn_base_addr,
					    entry_index);
	page_in_offset = virt_addr & MMU_MAPING_PAGE_MASK;
	real_phy_addr = (phy_page_addr << MMU_MAPING_PAGESIZE_SHIFFT)
				+ page_in_offset;

	*dest_addr = real_phy_addr;
	return SPRD_NO_ERR;
}
