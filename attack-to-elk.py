#!/usr/bin/env python3.6

__AUTHOR__ = 'Michael Hidalgo'
__VERSION__ = "1.0.0 Jan 2019"

"""
Install dependencies with:
pip install -r requirements.txt
"""

import utils
import json 
from Elastic_Search import ElasticSearch

def get_mitre_attack_technique_datasources(tactic_name,technique_name, technique_id, datasources):
    
    if datasources is not None:
        datasource_json = []
        for datasource in datasources:
            dts_json = {
                    "tactic_name": tactic_name,
                    "technique_name": technique_name,
                    "technique_id": technique_id,
                    "datasource" : datasource
                }  
            datasource_json.append(dts_json)
        return datasource_json
    return None

def get_mitre_attack_technique_platforms_and_permissions(tactic_name,technique_name, technique_id, technique):
    
        platforms_json = []
        platforms   = technique.get('x_mitre_platforms')
        permissions = technique.get('x_mitre_permissions_required')
        if platforms is not None:
            for platform in platforms:
                platform_json = {
                            "tactic_name"   : tactic_name,
                            "technique_name": technique_name,
                            "technique_id"  : technique_id,
                            "platform"      : platform
                        }  
                if permissions is not None:
                    for permission in permissions:
                        platform_json['permission'] = permission
                
                platforms_json.append(platform_json)
            return platforms_json
        return None

def get_mitre_attack_technique_groups(tactic_name,technique_name, technique_id,identifier,mitre_attack_relationships,  mitre_attack_threat_groups):   
    groups = []
    for relationship in mitre_attack_relationships:
        if (relationship.get('target_ref') == identifier):
            if ("intrusion" in relationship.get('source_ref')):
                source_ref                  = relationship.get('source_ref')
                group                       = get_mitre_attack_threat_group_by_id(source_ref, mitre_attack_threat_groups)
                group_id                    = None
                group_name                  = group.get('name')
                group_description           = group.get('description')
                group_aliases               = group.get('aliases')
                group_external_references   = group.get('external_references')
                group_id                    = get_mitre_attack_id(group_external_references)
        
                group_json = {
                            "tactic_name"   : tactic_name,
                            "technique_name": technique_name,
                            "technique_id"  : technique_id,
                            "group"         : group_name,
                            "group_id"      : group_id,
                            "description"   : group_description,
                            "aliases"       : group_aliases
                        } 
                groups.append(group_json)
    return groups   

def get_mitre_attack_technique_software(tactic_name,technique_name, technique_id,identifier, mitre_attack_relationships,mitre_attack_attack_software ):   
    
    software        = []
    for relationship in mitre_attack_relationships:
        if (relationship.get('target_ref') == identifier):
            if ('malware' in relationship.get('source_ref') or 'tool' in relationship.get('source_ref') ):
                source_ref          = relationship.get('source_ref')
                software_item       = get_mitre_attack_software_by_id(source_ref, mitre_attack_attack_software)
                software_id         = None
                software_name       = software_item.get('name')
                software_type       = software_item.get('type')
                software_aliases    = software_item.get('x_mitre_aliases')
                software_platforms  = software_item.get('x_mitre_platforms')
                external_references = software_item.get('external_references')
                software_id         = get_mitre_attack_id(external_references)
                software_json = {
                        "tactic_name"   : tactic_name,
                        "technique_name": technique_name,
                        "technique_id"  : technique_id,
                        "software_name" : software_name,
                        "software_id"   : software_id,
                        "software_type" : software_type,
                        "aliases"       : software_aliases,
                        "platforms"     : software_platforms
                        
                    } 
                software.append(software_json)
    return software                        
   
def get_mitre_attack_threat_group_by_id(group_id, groups):
    for group in groups:
        if group.get("id") == group_id:
            return group
    return None

def get_mitre_attack_software_by_id(software_id, attack_software):
    for soft in attack_software:
        if soft.get("id") == software_id:
            return soft
    return None

def get_mitre_attack_items_by_type(matrix, vtype):
    mitre_attack_item = []
    for item in matrix:
        if item.get('type') in vtype:
            mitre_attack_item.append(item)
    return mitre_attack_item

def get_mitre_attack_id(external_references):
    id = None
    if external_references is not None:
        for external_reference in external_references:
            if external_reference['source_name'] == 'mitre-attack':
                id = external_reference['external_id']
                break
    return id

""" Tactic name should be titled """
def standardize_mitre_attack_tactic_name(tactic):
    tactic_name = tactic.title().replace('-', ' ').replace("And", "and")
    return tactic_name

def parse_mitre_attack_techniques (mitre_attack_matrix):
    #Initializing json objects once.
    mitre_attack_software_types     = ['tool','malware', 'utility']
    mitre_attack_group_type         = "intrusion-set"
    mitre_attack_relationship_type  = "relationship"
    mitre_attack_techniques_type    = "attack-pattern"
    mitre_attack_techniques         = get_mitre_attack_items_by_type(mitre_attack_matrix, mitre_attack_techniques_type)
    mitre_attack_relationships      = get_mitre_attack_items_by_type(mitre_attack_matrix,mitre_attack_relationship_type)
    mitre_attack_threat_groups      = get_mitre_attack_items_by_type(mitre_attack_matrix, mitre_attack_group_type)
    mitre_attack_attack_software    = get_mitre_attack_items_by_type(mitre_attack_matrix,mitre_attack_software_types)

    techniques              = []
    data_sources            = []
    platforms               = []
    groups                  = []
    software                = []
    data_source_index       = ElasticSearch('mitre-attack-datasources').delete_index().create_index()
    platforms_index         = ElasticSearch('mitre-attack-platforms'  ).delete_index().create_index()
    technique_index         = ElasticSearch('mitre-attack-techniques' ).delete_index().create_index()
    groups_index            = ElasticSearch('mitre-attack-groups'     ).delete_index().create_index()
    software_index          = ElasticSearch('mitre-attack-software'   ).delete_index().create_index()
    
    for technique in mitre_attack_techniques:
        technique_json                  = {}
        item_id                         = technique.get('id')
        technique_external_references   = technique.get('external_references')
        technique_name                  = technique.get('name')
        technique_description           = technique.get('description')
        technique_id                    = get_mitre_attack_id(technique_external_references)

        # 1 to many: 1 technique can be associated to 1 or more tactics,
        # for example the tecnique Control Panel items.

        kill_chain_phases     = technique.get('kill_chain_phases')
        for kill_chain_phase in kill_chain_phases: 
            tactic_name           = standardize_mitre_attack_tactic_name(kill_chain_phase['phase_name'])
            data_sources          = get_mitre_attack_technique_datasources(tactic_name, technique_name,technique_id, technique.get('x_mitre_data_sources'))
            platforms             = get_mitre_attack_technique_platforms_and_permissions(tactic_name,technique_name, technique_id, technique)
            groups                = get_mitre_attack_technique_groups(tactic_name,technique_name,technique_id, item_id, mitre_attack_relationships,mitre_attack_threat_groups)
            software              = get_mitre_attack_technique_software(tactic_name,technique_name,technique_id, item_id,mitre_attack_relationships, mitre_attack_attack_software)
            
            if data_sources is not None:
                data_source_index.add_bulk(data_sources, 'datasources')

            if platforms is not None:
                platforms_index.add_bulk(platforms, 'platforms')

            if groups is not None:
                groups_index.add_bulk(groups, "groups")
            
            if software is not None:
                software_index.add_bulk(software, "software")
                
            technique_json = {
                "tactic_name"    : tactic_name,
                "technique_id"   : technique_id,
                "technique_name" : technique_name,
                "description"    : technique_description
            }  
            techniques.append(technique_json)

    """ Indexing the actual techniques """
    technique_index.add_bulk(techniques,"techniques")

def parse_mitre_attack_tactics(attack_matrix):
    tactics              = []
    # filters out MITRE ATT&CK tactics
    mitre_attack_tactics = get_mitre_attack_items_by_type(attack_matrix,"x-mitre-tactic")
    es = ElasticSearch('mitre-attack-tactics').delete_index().create_index()
    
    for tactic in mitre_attack_tactics:
        tactic_id                   = ''
        tactic_name                 = ''
        tactic_description          = ''
        tactic_description          = tactic.get('description')
        tactic_external_references  = tactic.get('external_references')
        tactic_id                   = get_mitre_attack_id(tactic_external_references)
        tactic_name                 = standardize_mitre_attack_tactic_name(tactic.get('name'))
        tactic_json = {
            "tactic_name": tactic_name,
            "tactic_id"  : tactic_id,
            "description": tactic_description
        }  
        tactics.append(tactic_json)  
      
    return es.add_bulk(tactics, 'tactics')   

def main():
    util                    = utils.utils()
    #loading MITRE ATT&CK enterpise matrix from file.

    mitre_attack_matrix     = json.loads(util.read_attack_matrix())['objects']
    
    parse_mitre_attack_tactics(mitre_attack_matrix)
    parse_mitre_attack_techniques(mitre_attack_matrix)

if __name__ == "__main__":
    print("Parsing and indexing MITRE ATT&CK")
    main()
    print('Parsing done')